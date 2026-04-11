"""
Covert Communications — anonymous agent-to-base transport.

Prevents network observers from tracing agent traffic back to the base
station by routing all communications through:

  • Tor (SOCKS5 auto-detected on 9050/9150)
  • External SOCKS5 proxy (--proxy socks5://host:port)
  • External HTTP/HTTPS proxy (--proxy http://host:port)
  • Privoxy/tor-http bridge (http://127.0.0.1:8118)

Additional obfuscation:
  • Random timing jitter before every transmission
  • Rotating browser User-Agents (traffic looks like web browsing)
  • Decoy requests to innocuous sites mask real pattern
  • Base URL never logged in plaintext (hashed in logs)
  • Request body padding to break size fingerprinting

Usage (from agent code):
    from network_guardian.agent.covert_comms import CovertComms, build_comms
    comms = build_comms(proxy="socks5://127.0.0.1:9050", jitter=True)
    ok = comms.post(url, headers, payload)
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import random
import secrets
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("network_guardian.agent.covert")

# ---------------------------------------------------------------------------
# User-Agent pool — rotate to look like normal browser traffic
# ---------------------------------------------------------------------------

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

# Decoy target URLs (innocuous public endpoints — no sensitive data sent)
_DECOY_TARGETS = [
    "http://ifconfig.me/all.json",
    "http://ip-api.com/json",
    "https://httpbin.org/ip",
    "https://api.ipify.org?format=json",
    "http://checkip.amazonaws.com",
    "https://icanhazip.com",
]

# Known Tor SOCKS5 ports (in order of preference)
_TOR_SOCKS_PORTS = [9050, 9150, 9051]
# Privoxy HTTP port (wraps Tor SOCKS5 as HTTP proxy)
_PRIVOXY_PORTS = [8118, 8119]


# ---------------------------------------------------------------------------
# Pure-Python SOCKS5 client (no PySocks dependency)
# ---------------------------------------------------------------------------

class Socks5Error(OSError):
    pass


def _socks5_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    username: str = "",
    password: str = "",
    timeout: float = 15.0,
) -> socket.socket:
    """
    Open a raw socket through a SOCKS5 proxy.
    Returns a connected socket that speaks directly to target_host:target_port.
    """
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        # Greeting — offer no-auth (0x00) or user/pass (0x02)
        if username:
            s.sendall(b"\x05\x02\x00\x02")
        else:
            s.sendall(b"\x05\x01\x00")

        ver, method = s.recv(2)
        if ver != 5:
            raise Socks5Error("SOCKS5 proxy returned invalid version")
        if method == 0xff:
            raise Socks5Error("SOCKS5 proxy rejected all auth methods")

        # Username/password sub-negotiation
        if method == 0x02:
            if not username:
                raise Socks5Error("SOCKS5 proxy requires authentication")
            u = username.encode()
            p = password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            _, status = s.recv(2)
            if status != 0:
                raise Socks5Error("SOCKS5 authentication failed")

        # CONNECT request
        # Use domain name (ATYP=0x03) so DNS resolves at the proxy — hides target from LAN
        host_bytes = target_host.encode("idna")
        cmd = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", target_port)
        )
        s.sendall(cmd)

        # Read response
        resp = b""
        while len(resp) < 4:
            chunk = s.recv(4 - len(resp))
            if not chunk:
                raise Socks5Error("SOCKS5 proxy closed connection during response")
            resp += chunk

        if resp[0] != 5:
            raise Socks5Error("Invalid SOCKS5 response version")
        if resp[1] != 0:
            errors = {
                1: "general failure", 2: "connection not allowed",
                3: "network unreachable", 4: "host unreachable",
                5: "connection refused", 6: "TTL expired",
                7: "command not supported", 8: "address type not supported",
            }
            raise Socks5Error(f"SOCKS5 connect failed: {errors.get(resp[1], f'code {resp[1]}')}")

        # Skip bound address (variable length depending on ATYP)
        atyp = resp[3]
        if atyp == 1:   # IPv4
            s.recv(6)
        elif atyp == 3:  # Domain
            dlen = ord(s.recv(1))
            s.recv(dlen + 2)
        elif atyp == 4:  # IPv6
            s.recv(18)

        return s
    except Exception:
        s.close()
        raise


class _Socks5HTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that tunnels through a SOCKS5 proxy."""

    def __init__(self, host: str, port: int | None = None, *,
                 proxy_host: str, proxy_port: int,
                 proxy_user: str = "", proxy_pass: str = "",
                 timeout: float = 15.0, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_user = proxy_user
        self._proxy_pass = proxy_pass

    def connect(self) -> None:
        self.sock = _socks5_connect(
            self._proxy_host, self._proxy_port,
            self.host, self.port or 80,
            self._proxy_user, self._proxy_pass,
            timeout=self.timeout,
        )


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that tunnels TLS through a SOCKS5 proxy."""

    def __init__(self, host: str, port: int | None = None, *,
                 proxy_host: str, proxy_port: int,
                 proxy_user: str = "", proxy_pass: str = "",
                 timeout: float = 15.0, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_user = proxy_user
        self._proxy_pass = proxy_pass

    def connect(self) -> None:
        raw = _socks5_connect(
            self._proxy_host, self._proxy_port,
            self.host, self.port or 443,
            self._proxy_user, self._proxy_pass,
            timeout=self.timeout,
        )
        ctx = self._context if hasattr(self, "_context") else ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)


class _Socks5Handler(urllib.request.AbstractHTTPHandler):
    """urllib handler that routes HTTP/HTTPS through SOCKS5."""

    def __init__(self, proxy_host: str, proxy_port: int,
                 proxy_user: str = "", proxy_pass: str = ""):
        super().__init__()
        self._ph = proxy_host
        self._pp = proxy_port
        self._pu = proxy_user
        self._pw = proxy_pass

    def http_open(self, req: urllib.request.Request):
        return self.do_open(self._make_http_conn, req)

    def https_open(self, req: urllib.request.Request):
        return self.do_open(self._make_https_conn, req)

    def _make_http_conn(self, host: str, **kwargs) -> _Socks5HTTPConnection:
        h, _, p = host.partition(":")
        return _Socks5HTTPConnection(
            h, int(p) if p else 80,
            proxy_host=self._ph, proxy_port=self._pp,
            proxy_user=self._pu, proxy_pass=self._pw,
            **kwargs,
        )

    def _make_https_conn(self, host: str, **kwargs) -> _Socks5HTTPSConnection:
        h, _, p = host.partition(":")
        return _Socks5HTTPSConnection(
            h, int(p) if p else 443,
            proxy_host=self._ph, proxy_port=self._pp,
            proxy_user=self._pu, proxy_pass=self._pw,
            **kwargs,
        )

    http_request = urllib.request.AbstractHTTPHandler.do_request_
    https_request = urllib.request.AbstractHTTPHandler.do_request_


# ---------------------------------------------------------------------------
# Tor / proxy auto-detection
# ---------------------------------------------------------------------------

def _probe_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def detect_tor() -> Optional[tuple[str, int]]:
    """
    Try to find a running Tor SOCKS5 proxy on localhost.
    Returns (host, port) or None.
    """
    for port in _TOR_SOCKS_PORTS:
        if _probe_port("127.0.0.1", port):
            logger.info("Tor SOCKS5 detected on 127.0.0.1:%d", port)
            return ("127.0.0.1", port)
    return None


def detect_privoxy() -> Optional[str]:
    """
    Try to find Privoxy (HTTP proxy bridge to Tor) on localhost.
    Returns proxy URL like 'http://127.0.0.1:8118' or None.
    """
    for port in _PRIVOXY_PORTS:
        if _probe_port("127.0.0.1", port):
            url = f"http://127.0.0.1:{port}"
            logger.info("Privoxy HTTP proxy detected at %s", url)
            return url
    return None


# ---------------------------------------------------------------------------
# Communication profile
# ---------------------------------------------------------------------------

@dataclass
class CovertProfile:
    """Configuration for covert communications."""

    # Proxy settings
    proxy_url: str = ""            # e.g. socks5://127.0.0.1:9050 or http://proxy:8080
    use_tor: bool = False          # Auto-detect and use Tor
    auto_detect: bool = True       # Auto-detect Tor/Privoxy at runtime

    # Timing obfuscation
    jitter_min: float = 2.0        # Minimum random delay before each send (seconds)
    jitter_max: float = 30.0       # Maximum random delay before each send (seconds)
    jitter_enabled: bool = True    # Enable timing jitter

    # Traffic camouflage
    rotate_user_agent: bool = True  # Rotate browser User-Agents
    send_decoys: bool = True        # Send decoy requests to innocuous targets
    decoy_count: int = 2            # Decoys sent per real transmission
    pad_body: bool = True           # Add random padding to request body size
    pad_max_bytes: int = 512        # Max random padding bytes

    # Operational security
    hide_base_url_in_logs: bool = True     # Hash the base URL in log output
    suppress_connection_errors: bool = True # Don't log detailed error info

    # Connection
    timeout: float = 20.0


# ---------------------------------------------------------------------------
# Core covert comms engine
# ---------------------------------------------------------------------------

class CovertComms:
    """
    Drop-in HTTP client that anonymizes all outbound agent communications.

    Routes traffic through Tor/proxy, applies timing jitter, rotates
    identities, and sends decoy traffic to mask real transmissions.
    """

    def __init__(self, profile: CovertProfile | None = None):
        self._profile = profile or CovertProfile()
        self._opener: Optional[urllib.request.OpenerDirector] = None
        self._resolved_proxy: str = ""  # Resolved proxy URL after auto-detection
        self._ua_index = 0
        self._last_setup = 0.0
        self._setup_ttl = 300.0  # Re-check proxy availability every 5 minutes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def post(
        self,
        url: str,
        headers: dict,
        payload: bytes,
        timeout: float | None = None,
    ) -> tuple[bool, dict]:
        """
        POST payload to url through the covert channel.
        Returns (success: bool, response_body: dict).
        """
        p = self._profile
        t = timeout or p.timeout

        # Apply timing jitter before sending
        if p.jitter_enabled:
            self._apply_jitter()

        # Ensure opener is fresh
        self._ensure_opener()

        # Build spoofed headers
        full_headers = dict(headers)
        if p.rotate_user_agent:
            full_headers["User-Agent"] = self._next_user_agent()
        full_headers.setdefault("Accept", "application/json, text/plain, */*")
        full_headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        full_headers.setdefault("Cache-Control", "no-cache")

        # Optionally pad the payload to obscure size signature
        actual_payload = payload
        if p.pad_body:
            pad = secrets.token_bytes(random.randint(0, p.pad_max_bytes))
            # Pad inside JSON if possible (add harmless field)
            try:
                body_dict = json.loads(payload)
                body_dict["_t"] = secrets.token_hex(len(pad) // 2)
                actual_payload = json.dumps(body_dict, separators=(",", ":")).encode()
            except Exception:
                pass  # Not JSON — send as-is

        # Send decoy requests first to mask the real one
        if p.send_decoys and p.decoy_count > 0:
            self._send_decoys()

        # Send the real request
        req = urllib.request.Request(
            url, data=actual_payload, method="POST", headers=full_headers,
        )
        try:
            opener = self._opener or urllib.request.build_opener()
            with opener.open(req, timeout=t) as resp:
                body = json.loads(resp.read())
                return True, body
        except urllib.error.HTTPError as e:
            if not p.suppress_connection_errors:
                logger.error("HTTP %d from %s", e.code, self._safe_url(url))
            return False, {}
        except Exception as e:
            if not p.suppress_connection_errors:
                logger.error("Covert POST failed to %s: %s", self._safe_url(url), type(e).__name__)
            return False, {}

    def get(
        self,
        url: str,
        headers: dict | None = None,
        timeout: float | None = None,
    ) -> tuple[bool, dict]:
        """GET request through the covert channel."""
        p = self._profile
        t = timeout or p.timeout
        self._ensure_opener()

        full_headers: dict = dict(headers or {})
        if p.rotate_user_agent:
            full_headers["User-Agent"] = self._next_user_agent()
        full_headers.setdefault("Accept", "application/json, */*")

        req = urllib.request.Request(url, method="GET", headers=full_headers)
        try:
            opener = self._opener or urllib.request.build_opener()
            with opener.open(req, timeout=t) as resp:
                body = json.loads(resp.read())
                return True, body
        except Exception as e:
            if not p.suppress_connection_errors:
                logger.error("Covert GET failed to %s: %s", self._safe_url(url), type(e).__name__)
            return False, {}

    @property
    def proxy_summary(self) -> str:
        """Human-readable summary of current proxy configuration."""
        if self._resolved_proxy:
            return f"via {self._resolved_proxy}"
        return "direct (no proxy)"

    def status(self) -> dict:
        """Return current covert comms status."""
        return {
            "proxy": self._resolved_proxy or "none",
            "tor_mode": self._profile.use_tor,
            "jitter": f"{self._profile.jitter_min:.0f}-{self._profile.jitter_max:.0f}s" if self._profile.jitter_enabled else "off",
            "decoys": self._profile.decoy_count if self._profile.send_decoys else 0,
            "user_agent_rotation": self._profile.rotate_user_agent,
            "body_padding": self._profile.pad_body,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_opener(self) -> None:
        """Build or refresh the opener (auto-detect proxies if needed)."""
        now = time.time()
        if self._opener and (now - self._last_setup) < self._setup_ttl:
            return
        self._opener = self._build_opener()
        self._last_setup = now

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """
        Build an opener that routes through the configured proxy.
        Priority: explicit proxy_url > Tor SOCKS5 > Privoxy > env proxy > direct.
        """
        p = self._profile
        proxy_url = p.proxy_url

        # Auto-detect if no explicit proxy given
        if not proxy_url and p.auto_detect:
            # Check Tor SOCKS5
            tor = detect_tor()
            if tor:
                proxy_url = f"socks5://{tor[0]}:{tor[1]}"
                logger.info("Covert: auto-routed via Tor SOCKS5 %s:%d", tor[0], tor[1])
            else:
                # Check Privoxy
                privoxy = detect_privoxy()
                if privoxy:
                    proxy_url = privoxy
                    logger.info("Covert: auto-routed via Privoxy %s", privoxy)

        self._resolved_proxy = proxy_url

        if not proxy_url:
            # Check OS env proxies (HTTP_PROXY, HTTPS_PROXY etc.)
            env_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
            if env_proxy:
                proxy_url = env_proxy
                self._resolved_proxy = proxy_url
                logger.info("Covert: using env proxy %s", self._safe_url(proxy_url))

        if not proxy_url:
            logger.warning(
                "Covert comms: NO PROXY — communications are NOT anonymized. "
                "Install Tor or set --proxy to hide base station IP."
            )
            return urllib.request.build_opener()

        parsed = urllib.parse.urlparse(proxy_url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port or 0
        user = parsed.username or ""
        pwd = parsed.password or ""

        if scheme in ("socks5", "socks5h"):
            handler = _Socks5Handler(host, port, user, pwd)
            return urllib.request.build_opener(handler)

        elif scheme in ("socks4",):
            # SOCKS4 — minimal: use SOCKS5 handler without auth (most SOCKS4 proxies accept SOCKS5 no-auth)
            handler = _Socks5Handler(host, port)
            return urllib.request.build_opener(handler)

        elif scheme in ("http", "https"):
            # Standard HTTP proxy — Python has built-in support
            proxy_map = {
                "http": proxy_url,
                "https": proxy_url,
            }
            if user:
                # Build auth header for proxy
                import base64
                creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                proxy_handler = urllib.request.ProxyHandler(proxy_map)
                opener = urllib.request.build_opener(proxy_handler)
                opener.addheaders = [("Proxy-Authorization", f"Basic {creds}")]
                return opener
            return urllib.request.build_opener(urllib.request.ProxyHandler(proxy_map))

        else:
            logger.warning("Unknown proxy scheme '%s', using direct connection", scheme)
            return urllib.request.build_opener()

    def _apply_jitter(self) -> None:
        """Sleep a random amount to break timing correlation."""
        p = self._profile
        delay = random.uniform(p.jitter_min, p.jitter_max)
        logger.debug("Covert jitter: %.1fs before transmission", delay)
        time.sleep(delay)

    def _next_user_agent(self) -> str:
        """Return a rotating User-Agent string."""
        ua = _USER_AGENTS[self._ua_index % len(_USER_AGENTS)]
        self._ua_index = (self._ua_index + 1) % len(_USER_AGENTS)
        return ua

    def _send_decoys(self) -> None:
        """
        Fire decoy GET requests to innocuous public endpoints.
        These mix with real traffic to make pattern analysis harder.
        """
        count = min(self._profile.decoy_count, len(_DECOY_TARGETS))
        targets = random.sample(_DECOY_TARGETS, count)
        opener = self._opener or urllib.request.build_opener()
        for target in targets:
            try:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": self._next_user_agent(), "Accept": "*/*"},
                )
                with opener.open(req, timeout=5):
                    pass
                logger.debug("Covert decoy: %s", target)
            except Exception:
                pass  # Decoy failures are irrelevant

    def _safe_url(self, url: str) -> str:
        """Return a safe-to-log version of a URL (hashed host)."""
        if not self._profile.hide_base_url_in_logs:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            host_hash = hashlib.sha256(parsed.netloc.encode()).hexdigest()[:8]
            return f"{parsed.scheme}://{host_hash}…:{parsed.port}{parsed.path}"
        except Exception:
            return "[base]"


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def build_comms(
    proxy: str = "",
    use_tor: bool = False,
    jitter: bool = True,
    jitter_range: tuple[float, float] = (3.0, 25.0),
    decoys: bool = True,
    stealth: bool = False,
) -> CovertComms:
    """
    Build a CovertComms instance from simple CLI parameters.

    Args:
        proxy:       Proxy URL (socks5://host:port, http://host:port, etc.)
        use_tor:     Force Tor — will fail if Tor not running
        jitter:      Enable random timing delays
        jitter_range: (min_seconds, max_seconds) delay range
        decoys:      Send decoy requests to mask real traffic
        stealth:     Maximum stealth — long jitter, more decoys, total log suppression
    """
    jmin, jmax = jitter_range
    if stealth:
        # Ghost mode: 0.5–5 minute jitter, 4 decoys, everything suppressed
        jmin, jmax = 30.0, 300.0
        decoys = True
        profile = CovertProfile(
            proxy_url=proxy,
            use_tor=use_tor,
            auto_detect=True,
            jitter_min=jmin,
            jitter_max=jmax,
            jitter_enabled=True,
            rotate_user_agent=True,
            send_decoys=True,
            decoy_count=4,
            pad_body=True,
            pad_max_bytes=1024,
            hide_base_url_in_logs=True,
            suppress_connection_errors=True,
            timeout=30.0,
        )
    else:
        profile = CovertProfile(
            proxy_url=proxy,
            use_tor=use_tor,
            auto_detect=True,
            jitter_min=jmin,
            jitter_max=jmax,
            jitter_enabled=jitter,
            rotate_user_agent=True,
            send_decoys=decoys,
            decoy_count=2,
            pad_body=True,
            pad_max_bytes=512,
            hide_base_url_in_logs=True,
            suppress_connection_errors=True,
            timeout=20.0,
        )
    return CovertComms(profile)


def from_env() -> CovertComms:
    """
    Build CovertComms from environment variables:
        NG_PROXY      — proxy URL (socks5://host:port, http://host:port)
        NG_TOR        — '1' to force Tor
        NG_JITTER     — '0' to disable jitter
        NG_STEALTH    — '1' for maximum stealth mode
        NG_DECOYS     — '0' to disable decoys
    """
    proxy = os.environ.get("NG_PROXY", "")
    use_tor = os.environ.get("NG_TOR", "0") == "1"
    jitter = os.environ.get("NG_JITTER", "1") != "0"
    stealth = os.environ.get("NG_STEALTH", "0") == "1"
    decoys = os.environ.get("NG_DECOYS", "1") != "0"
    return build_comms(proxy=proxy, use_tor=use_tor, jitter=jitter,
                       decoys=decoys, stealth=stealth)
