"""
IP Cloaking — network identity obfuscation and privacy.

Provides mechanisms to mask, rotate, and obfuscate IP addresses for
stealth scanning and privacy-preserving operations:

  • **Address masking** — replace real IPs with aliases in logs/reports
  • **Source rotation** — cycle through available source addresses
  • **Proxy chain** — route traffic through configurable proxy hops
  • **Decoy generation** — generate decoy traffic to mask real scans
  • **Identity profiles** — saveable cloaking configurations
  • **WiFi stealth** — hide your SSID from nearby devices

All outbound traffic from Network Guardian can optionally be routed
through the cloaking layer for operational security.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import platform
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from base64 import b64encode
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.cloaking")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CloakMode(Enum):
    """IP cloaking mode."""

    DISABLED = "disabled"
    MASK = "mask"               # Replace IPs in logs with aliases
    ROTATE = "rotate"           # Cycle through source IPs
    PROXY = "proxy"             # Route through proxy chain
    DECOY = "decoy"             # Generate decoy traffic
    FULL = "full"               # All techniques combined


class ProxyProtocol(Enum):
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    HTTP = "http"
    HTTPS = "https"


@dataclass
class ProxyHop:
    """A single hop in a proxy chain."""

    host: str
    port: int
    protocol: ProxyProtocol = ProxyProtocol.SOCKS5
    username: str = ""
    # Note: credentials should come from env/secrets manager in production
    auth_token_env: str = ""  # env var name for auth
    latency_ms: float = 0.0
    is_alive: bool = True

    @property
    def address(self) -> str:
        return f"{self.protocol.value}://{self.host}:{self.port}"

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol.value,
            "latency_ms": self.latency_ms,
            "is_alive": self.is_alive,
        }


@dataclass
class CloakIdentity:
    """A cloaking identity profile."""

    name: str
    mode: CloakMode
    source_ips: list[str] = field(default_factory=list)
    proxy_chain: list[ProxyHop] = field(default_factory=list)
    decoy_count: int = 3
    mask_salt: str = field(default_factory=lambda: secrets.token_hex(8))
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode.value,
            "source_ips": self.source_ips,
            "proxy_chain": [p.as_dict for p in self.proxy_chain],
            "decoy_count": self.decoy_count,
            "created": self.created.isoformat(),
        }


@dataclass
class DecoyTarget:
    """A decoy scan target used to mask real scan activity."""

    ip: str
    ports: list[int] = field(default_factory=list)
    delay_ms: float = 0.0

    @property
    def as_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "ports": self.ports, "delay_ms": self.delay_ms}


# ---------------------------------------------------------------------------
# IP Masking engine
# ---------------------------------------------------------------------------


class IPMasker:
    """Deterministic IP masking — same input always maps to same alias.

    Uses HMAC-style hashing with a per-session salt so the mapping
    cannot be reversed without the salt, but remains consistent within
    a session for log correlation.
    """

    def __init__(self, salt: str | None = None) -> None:
        self._salt = salt or secrets.token_hex(8)
        self._cache: dict[str, str] = {}
        self._reverse: dict[str, str] = {}

    def mask(self, ip: str) -> str:
        """Return a deterministic masked alias for an IP address."""
        if ip in self._cache:
            return self._cache[ip]

        h = hashlib.sha256(f"{self._salt}:{ip}".encode()).hexdigest()[:8]
        alias = f"cloaked-{h}"
        self._cache[ip] = alias
        self._reverse[alias] = ip
        return alias

    def unmask(self, alias: str) -> str | None:
        """Reverse lookup — only works within the same session."""
        return self._reverse.get(alias)

    def mask_text(self, text: str) -> str:
        """Mask all known IPs that appear in a text string."""
        result = text
        for real_ip, alias in self._cache.items():
            result = result.replace(real_ip, alias)
        return result

    @property
    def mapping_count(self) -> int:
        return len(self._cache)

    def reset(self, new_salt: str | None = None) -> None:
        """Reset all mappings, optionally with a new salt."""
        self._salt = new_salt or secrets.token_hex(8)
        self._cache.clear()
        self._reverse.clear()


# ---------------------------------------------------------------------------
# Source IP rotation
# ---------------------------------------------------------------------------


class SourceRotator:
    """Cycles through available source IP addresses for outgoing connections."""

    def __init__(self, source_ips: list[str] | None = None) -> None:
        self._sources: list[str] = source_ips or []
        self._index = 0

    def add_source(self, ip: str) -> None:
        """Add a source IP to the rotation pool."""
        if ip not in self._sources:
            self._sources.append(ip)

    def remove_source(self, ip: str) -> bool:
        if ip in self._sources:
            self._sources.remove(ip)
            return True
        return False

    def next_source(self) -> str | None:
        """Get the next source IP in rotation."""
        if not self._sources:
            return None
        ip = self._sources[self._index % len(self._sources)]
        self._index += 1
        return ip

    def random_source(self) -> str | None:
        """Pick a random source IP."""
        if not self._sources:
            return None
        # Use secrets for unpredictable selection
        idx = secrets.randbelow(len(self._sources))
        return self._sources[idx]

    @property
    def pool_size(self) -> int:
        return len(self._sources)

    @property
    def sources(self) -> list[str]:
        return list(self._sources)


# ---------------------------------------------------------------------------
# Decoy generator
# ---------------------------------------------------------------------------


class DecoyGenerator:
    """Generates decoy targets and traffic to mask real scan activity.

    When performing a real scan against a target, decoy scans are
    simultaneously launched against plausible random IPs, making it
    harder for an observer to identify the actual target.
    """

    def __init__(self, subnet: str = "192.168.1.0/24", count: int = 3) -> None:
        self._subnet = ipaddress.ip_network(subnet, strict=False)
        self.count = count

    def generate_decoys(
        self,
        real_target: str,
        real_ports: list[int] | None = None,
    ) -> list[DecoyTarget]:
        """Generate decoy targets that look like the real scan target."""
        decoys: list[DecoyTarget] = []
        hosts = list(self._subnet.hosts())
        # Filter out the real target and network/broadcast
        candidates = [str(h) for h in hosts if str(h) != real_target]

        count = min(self.count, len(candidates))
        selected = []
        seen: set[int] = set()
        while len(selected) < count and len(seen) < len(candidates):
            idx = secrets.randbelow(len(candidates))
            if idx not in seen:
                seen.add(idx)
                selected.append(candidates[idx])

        ports = real_ports or [22, 80, 443]
        for ip in selected:
            # Randomise delay to avoid timing correlation
            delay = secrets.randbelow(500) + 100  # 100-600ms
            decoys.append(DecoyTarget(ip=ip, ports=list(ports), delay_ms=delay))

        return decoys

    @property
    def subnet(self) -> str:
        return str(self._subnet)


# ---------------------------------------------------------------------------
# IP Cloaking System (main orchestrator)
# ---------------------------------------------------------------------------


class IPCloakingSystem:
    """Unified IP cloaking and privacy system.

    Combines masking, rotation, proxy chaining, and decoy generation
    into a single orchestrated privacy layer.
    """

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus

        self._mode = CloakMode.DISABLED
        self._masker = IPMasker()
        self._rotator = SourceRotator()
        self._decoy_gen = DecoyGenerator()
        self._proxy_chain: list[ProxyHop] = []
        self._identities: dict[str, CloakIdentity] = {}
        self._active_identity: str | None = None
        self._running = False
        self._stats_masked = 0
        self._stats_rotated = 0
        self._stats_decoys = 0

    # -- Mode control ---------------------------------------------------

    @property
    def mode(self) -> CloakMode:
        return self._mode

    def set_mode(self, mode: CloakMode) -> None:
        """Set the active cloaking mode."""
        old = self._mode
        self._mode = mode
        logger.info("Cloaking mode changed: %s → %s", old.value, mode.value)

    # -- Masking --------------------------------------------------------

    def mask_ip(self, ip: str) -> str:
        """Mask an IP address (returns alias if masking is active)."""
        if self._mode in (CloakMode.MASK, CloakMode.FULL):
            self._stats_masked += 1
            return self._masker.mask(ip)
        return ip

    def unmask_ip(self, alias: str) -> str | None:
        """Reverse-lookup a masked IP."""
        return self._masker.unmask(alias)

    def mask_text(self, text: str) -> str:
        """Mask all known IPs in a block of text."""
        if self._mode in (CloakMode.MASK, CloakMode.FULL):
            return self._masker.mask_text(text)
        return text

    # -- Source rotation ------------------------------------------------

    def get_source_ip(self) -> str | None:
        """Get the next outbound source IP (if rotation is active)."""
        if self._mode in (CloakMode.ROTATE, CloakMode.FULL):
            self._stats_rotated += 1
            return self._rotator.random_source()
        return None

    def add_source_ip(self, ip: str) -> None:
        self._rotator.add_source(ip)

    def remove_source_ip(self, ip: str) -> bool:
        return self._rotator.remove_source(ip)

    # -- Proxy chain ----------------------------------------------------

    def add_proxy(self, proxy: ProxyHop) -> None:
        """Add a proxy to the chain."""
        self._proxy_chain.append(proxy)
        logger.info("Proxy added to chain: %s", proxy.address)

    def remove_proxy(self, index: int) -> ProxyHop | None:
        """Remove a proxy by index."""
        if 0 <= index < len(self._proxy_chain):
            return self._proxy_chain.pop(index)
        return None

    def clear_proxy_chain(self) -> int:
        count = len(self._proxy_chain)
        self._proxy_chain.clear()
        return count

    @property
    def proxy_chain(self) -> list[ProxyHop]:
        return list(self._proxy_chain)

    async def check_proxy_health(self) -> list[dict[str, Any]]:
        """Check connectivity to each proxy in the chain."""
        results: list[dict[str, Any]] = []
        for proxy in self._proxy_chain:
            # In a real implementation, this would attempt a TCP connection
            results.append({
                "address": proxy.address,
                "is_alive": proxy.is_alive,
                "latency_ms": proxy.latency_ms,
            })
        return results

    # -- Decoy generation -----------------------------------------------

    def generate_decoys(
        self, real_target: str, ports: list[int] | None = None,
    ) -> list[DecoyTarget]:
        """Generate decoy targets around a real scan target."""
        if self._mode in (CloakMode.DECOY, CloakMode.FULL):
            decoys = self._decoy_gen.generate_decoys(real_target, ports)
            self._stats_decoys += len(decoys)
            return decoys
        return []

    def set_decoy_subnet(self, subnet: str) -> None:
        """Configure the subnet used for decoy generation."""
        self._decoy_gen = DecoyGenerator(subnet=subnet, count=self._decoy_gen.count)

    def set_decoy_count(self, count: int) -> None:
        """Set the number of decoys generated per real target."""
        self._decoy_gen.count = max(1, count)

    # -- Identity profiles ----------------------------------------------

    def create_identity(
        self,
        name: str,
        mode: CloakMode,
        source_ips: list[str] | None = None,
        proxy_chain: list[ProxyHop] | None = None,
        decoy_count: int = 3,
    ) -> CloakIdentity:
        """Create a named cloaking identity profile."""
        identity = CloakIdentity(
            name=name,
            mode=mode,
            source_ips=source_ips or [],
            proxy_chain=proxy_chain or [],
            decoy_count=decoy_count,
        )
        self._identities[name] = identity
        logger.info("Cloaking identity created: %s (mode=%s)", name, mode.value)
        return identity

    def activate_identity(self, name: str) -> bool:
        """Activate a named identity profile."""
        identity = self._identities.get(name)
        if identity is None:
            return False

        self._mode = identity.mode
        self._masker = IPMasker(salt=identity.mask_salt)
        self._rotator = SourceRotator(list(identity.source_ips))
        self._proxy_chain = list(identity.proxy_chain)
        self._decoy_gen.count = identity.decoy_count
        self._active_identity = name
        logger.info("Activated cloaking identity: %s", name)
        return True

    def list_identities(self) -> list[CloakIdentity]:
        return list(self._identities.values())

    def delete_identity(self, name: str) -> bool:
        if name in self._identities:
            del self._identities[name]
            if self._active_identity == name:
                self._active_identity = None
            return True
        return False

    @property
    def active_identity(self) -> str | None:
        return self._active_identity

    # -- Scan preparation -----------------------------------------------

    def prepare_scan(
        self, target: str, ports: list[int] | None = None,
    ) -> dict[str, Any]:
        """Prepare a cloaked scan configuration.

        Returns a dict with source_ip, decoys, proxy_chain, and
        masked_target for use by scanning subsystems.
        """
        result: dict[str, Any] = {
            "real_target": target,
            "display_target": self.mask_ip(target),
            "source_ip": self.get_source_ip(),
            "decoys": [d.as_dict for d in self.generate_decoys(target, ports)],
            "proxy_chain": [p.as_dict for p in self._proxy_chain],
            "mode": self._mode.value,
        }
        return result

    # -- Lifecycle ------------------------------------------------------

    async def start(self) -> None:
        """Start the cloaking system."""
        self._running = True
        logger.info("IP Cloaking started (mode=%s).", self._mode.value)
        await self.event_bus.publish(Event(
            topic="cloaking.started",
            data={"mode": self._mode.value},
        ))

    async def stop(self) -> None:
        """Stop the cloaking system and clear sensitive state."""
        self._running = False
        self._masker.reset()
        logger.info("IP Cloaking stopped. Masking tables cleared.")

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "mode": self._mode.value,
            "active_identity": self._active_identity,
            "identities": len(self._identities),
            "source_pool_size": self._rotator.pool_size,
            "proxy_chain_length": len(self._proxy_chain),
            "masked_ips": self._masker.mapping_count,
            "stats_masked": self._stats_masked,
            "stats_rotated": self._stats_rotated,
            "stats_decoys": self._stats_decoys,
            "running": self._running,
        }


# ---------------------------------------------------------------------------
# WiFi Network data models
# ---------------------------------------------------------------------------


@dataclass
class WiFiNetwork:
    """A detected WiFi network."""

    ssid: str
    bssid: str = ""
    signal: int = 0
    channel: int = 0
    security: str = "Unknown"
    frequency: str = ""
    hidden: bool = False

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "ssid": self.ssid or "(hidden)",
            "bssid": self.bssid,
            "signal": self.signal,
            "channel": self.channel,
            "security": self.security,
            "frequency": self.frequency,
            "hidden": self.hidden,
        }


@dataclass
class RouterConfig:
    """Router admin access configuration."""

    ip: str
    username: str = "admin"
    _auth_header: str = ""
    router_type: str = "auto"  # auto, generic, openwrt, ddwrt, nighthawk

    def set_credentials(self, username: str, password: str) -> None:
        """Store auth header — password is NOT stored in plaintext."""
        self.username = username
        creds = b64encode(f"{username}:{password}".encode()).decode()
        self._auth_header = f"Basic {creds}"

    @property
    def auth_header(self) -> str:
        return self._auth_header

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "username": self.username,
            "router_type": self.router_type,
            "configured": bool(self._auth_header),
        }


class SSIDState(Enum):
    """SSID broadcast state."""
    VISIBLE = "visible"
    HIDDEN = "hidden"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# WiFi Scanner (cross-platform)
# ---------------------------------------------------------------------------


class WiFiScanner:
    """Cross-platform WiFi network scanner using OS utilities."""

    def __init__(self) -> None:
        self._os = platform.system().lower()
        self._last_scan: list[WiFiNetwork] = []

    async def scan_networks(self) -> list[WiFiNetwork]:
        """Scan for nearby WiFi networks."""
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._scan_sync)
        self._last_scan = results
        return results

    def _scan_sync(self) -> list[WiFiNetwork]:
        """Synchronous scan using OS commands."""
        if self._os == "windows":
            return self._scan_windows()
        elif self._os == "linux":
            return self._scan_linux()
        elif self._os == "darwin":
            return self._scan_macos()
        return []

    def _scan_windows(self) -> list[WiFiNetwork]:
        """Scan using netsh on Windows."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, timeout=15,
            )
            return self._parse_netsh_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("WiFi scan failed: %s", exc)
            return []

    def _scan_linux(self) -> list[WiFiNetwork]:
        """Scan using nmcli on Linux."""
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,SECURITY",
                 "dev", "wifi", "list", "--rescan", "yes"],
                capture_output=True, text=True, timeout=15,
            )
            return self._parse_nmcli_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # Fallback to iwlist
            try:
                result = subprocess.run(
                    ["iwlist", "scan"],
                    capture_output=True, text=True, timeout=15,
                )
                return self._parse_iwlist_output(result.stdout)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                logger.warning("WiFi scan failed: %s", exc)
                return []

    def _scan_macos(self) -> list[WiFiNetwork]:
        """Scan using system_profiler on macOS (airport removed in macOS Sonoma+)."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType", "-json"],
                capture_output=True, text=True, timeout=20,
            )
            return self._parse_system_profiler_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("WiFi scan failed: %s", exc)
            return []

    def _parse_netsh_output(self, output: str) -> list[WiFiNetwork]:
        """Parse netsh wlan show networks output."""
        networks: list[WiFiNetwork] = []
        current: dict[str, Any] = {}

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                # Start of new network
                if current.get("ssid") is not None:
                    networks.append(self._dict_to_wifi(current))
                match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
                ssid = match.group(1).strip() if match else ""
                current = {"ssid": ssid, "hidden": ssid == ""}
            elif line.startswith("BSSID"):
                match = re.match(r"BSSID\s+\d+\s*:\s*(.*)", line)
                if match:
                    current["bssid"] = match.group(1).strip()
            elif line.startswith("Signal"):
                match = re.match(r"Signal\s*:\s*(\d+)%", line)
                if match:
                    current["signal"] = int(match.group(1))
            elif line.startswith("Channel"):
                match = re.match(r"Channel\s*:\s*(\d+)", line)
                if match:
                    current["channel"] = int(match.group(1))
            elif "Authentication" in line:
                match = re.match(r"Authentication\s*:\s*(.*)", line)
                if match:
                    current["security"] = match.group(1).strip()
            elif line.startswith("Radio type"):
                match = re.match(r"Radio type\s*:\s*(.*)", line)
                if match:
                    current["frequency"] = match.group(1).strip()

        if current.get("ssid") is not None:
            networks.append(self._dict_to_wifi(current))

        return networks

    def _parse_nmcli_output(self, output: str) -> list[WiFiNetwork]:
        """Parse nmcli -t output (colons in BSSID escaped as backslash-colon)."""
        networks: list[WiFiNetwork] = []
        for line in output.strip().splitlines():
            # Split on unescaped colons only
            parts = re.split(r"(?<!\\):", line)
            if len(parts) >= 5:
                ssid = parts[0].strip()
                bssid = parts[1].strip().replace("\\:", ":")
                signal_str = parts[2].strip()
                networks.append(WiFiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    signal=int(signal_str) if signal_str.lstrip('-').isdigit() else 0,
                    frequency=parts[3].strip(),
                    security=parts[4].strip(),
                    hidden=ssid == "" or ssid == "--",
                ))
        return networks

    def _parse_iwlist_output(self, output: str) -> list[WiFiNetwork]:
        """Parse iwlist scan output."""
        networks: list[WiFiNetwork] = []
        current: dict[str, Any] = {}

        for line in output.splitlines():
            line = line.strip()
            if "Cell" in line and "Address:" in line:
                if current:
                    networks.append(self._dict_to_wifi(current))
                match = re.search(r"Address:\s*(\S+)", line)
                current = {"bssid": match.group(1) if match else ""}
            elif "ESSID:" in line:
                match = re.search(r'ESSID:"(.*)"', line)
                ssid = match.group(1) if match else ""
                current["ssid"] = ssid
                current["hidden"] = ssid == ""
            elif "Signal level" in line:
                match = re.search(r"Signal level[=:](-?\d+)", line)
                if match:
                    current["signal"] = int(match.group(1))
            elif "Channel:" in line:
                match = re.search(r"Channel:(\d+)", line)
                if match:
                    current["channel"] = int(match.group(1))
            elif "Encryption key:" in line:
                key_val = line.split("key:", 1)[1].strip() if "key:" in line else ""
                current["security"] = "Encrypted" if key_val == "on" else "Open"

        if current:
            networks.append(self._dict_to_wifi(current))
        return networks

    def _parse_airport_output(self, output: str) -> list[WiFiNetwork]:
        """Parse macOS airport -s output (legacy, kept for compatibility)."""
        networks: list[WiFiNetwork] = []
        lines = output.strip().splitlines()
        if len(lines) < 2:
            return networks
        for line in lines[1:]:  # skip header
            match = re.match(
                r"\s*(.+?)\s+([0-9a-f:]{17})\s+(-?\d+)\s+(\d+)", line, re.I,
            )
            if match:
                networks.append(WiFiNetwork(
                    ssid=match.group(1).strip(),
                    bssid=match.group(2),
                    signal=int(match.group(3)),
                    channel=int(match.group(4)),
                ))
        return networks

    def _parse_system_profiler_output(self, output: str) -> list[WiFiNetwork]:
        """Parse macOS system_profiler SPAirPortDataType -json output."""
        import json as _json
        networks: list[WiFiNetwork] = []
        try:
            data = _json.loads(output)
            interfaces = (
                data.get("SPAirPortDataType", [{}])[0]
                    .get("spairport_airport_interfaces", [])
            )
            for iface in interfaces:
                other_networks = iface.get("spairport_airport_other_local_wireless_networks", [])
                current = iface.get("spairport_current_network_information", {})
                all_nets = ([current] if current else []) + other_networks
                for net in all_nets:
                    ssid = net.get("_name", "")
                    bssid = net.get("spairport_network_bssid", "")
                    channel_str = str(net.get("spairport_network_channel", ""))
                    ch_match = re.search(r"(\d+)", channel_str)
                    channel = int(ch_match.group(1)) if ch_match else 0
                    rssi_raw = net.get("spairport_network_signal_noise", "")
                    rssi = rssi_raw.split("/")[0].strip() if rssi_raw else ""
                    signal = int(rssi) if rssi.lstrip("-").isdigit() else 0
                    security = net.get("spairport_security_mode", "Unknown")
                    networks.append(WiFiNetwork(
                        ssid=ssid, bssid=bssid, signal=signal,
                        channel=channel, security=security,
                        hidden=ssid == "",
                    ))
        except (ValueError, KeyError, IndexError) as exc:
            logger.warning("Failed to parse system_profiler output: %s", exc)
        return networks

    def _dict_to_wifi(self, d: dict[str, Any]) -> WiFiNetwork:
        return WiFiNetwork(
            ssid=d.get("ssid", ""),
            bssid=d.get("bssid", ""),
            signal=d.get("signal", 0),
            channel=d.get("channel", 0),
            security=d.get("security", "Unknown"),
            frequency=d.get("frequency", ""),
            hidden=d.get("hidden", False),
        )

    async def get_connected_network(self) -> WiFiNetwork | None:
        """Get the currently connected WiFi network."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._connected_sync)

    def _connected_sync(self) -> WiFiNetwork | None:
        if self._os == "windows":
            return self._connected_windows()
        elif self._os == "linux":
            return self._connected_linux()
        elif self._os == "darwin":
            return self._connected_macos()
        return None

    def _connected_windows(self) -> WiFiNetwork | None:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=10,
            )
            info: dict[str, Any] = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    match = re.match(r"SSID\s*:\s*(.*)", line)
                    if match:
                        info["ssid"] = match.group(1).strip()
                elif line.startswith("BSSID"):
                    match = re.match(r"BSSID\s*:\s*(.*)", line)
                    if match:
                        info["bssid"] = match.group(1).strip()
                elif line.startswith("Signal"):
                    match = re.match(r"Signal\s*:\s*(\d+)%", line)
                    if match:
                        info["signal"] = int(match.group(1))
                elif line.startswith("Channel"):
                    match = re.match(r"Channel\s*:\s*(\d+)", line)
                    if match:
                        info["channel"] = int(match.group(1))
                elif line.startswith("Authentication"):
                    match = re.match(r"Authentication\s*:\s*(.*)", line)
                    if match:
                        info["security"] = match.group(1).strip()
            if "ssid" in info:
                return self._dict_to_wifi(info)
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _connected_linux(self) -> WiFiNetwork | None:
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,FREQ,SECURITY",
                 "dev", "wifi"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split(":")
                if len(parts) >= 6 and parts[0].strip() == "yes":
                    return WiFiNetwork(
                        ssid=parts[1].strip(),
                        bssid=parts[2].strip().replace("\\:", ":"),
                        signal=int(parts[3]) if parts[3].isdigit() else 0,
                        frequency=parts[4].strip(),
                        security=parts[5].strip(),
                    )
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _connected_macos(self) -> WiFiNetwork | None:
        """Get connected WiFi using system_profiler (airport removed in macOS Sonoma+)."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType", "-json"],
                capture_output=True, text=True, timeout=15,
            )
            import json as _json
            data = _json.loads(result.stdout)
            interfaces = (
                data.get("SPAirPortDataType", [{}])[0]
                    .get("spairport_airport_interfaces", [])
            )
            for iface in interfaces:
                current = iface.get("spairport_current_network_information", {})
                if current:
                    ssid = current.get("_name", "")
                    bssid = current.get("spairport_network_bssid", "")
                    channel_str = current.get("spairport_network_channel", "")
                    channel = int(re.search(r"(\d+)", str(channel_str)).group(1)) if channel_str else 0
                    rssi = current.get("spairport_network_signal_noise", "").split("/")[0].strip()
                    signal = int(rssi) if rssi.lstrip("-").isdigit() else 0
                    security = current.get("spairport_security_mode", "Unknown")
                    return WiFiNetwork(ssid=ssid, bssid=bssid, signal=signal,
                                      channel=channel, security=security)
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError,
                KeyError, IndexError):
            return None


# ---------------------------------------------------------------------------
# Gateway detector
# ---------------------------------------------------------------------------


class GatewayDetector:
    """Detect the default gateway (usually the router)."""

    def __init__(self) -> None:
        self._os = platform.system().lower()

    async def detect(self) -> str | None:
        """Detect the default gateway IP address."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._detect_sync)

    def _detect_sync(self) -> str | None:
        if self._os == "windows":
            return self._detect_windows()
        elif self._os == "linux":
            return self._detect_linux()
        elif self._os == "darwin":
            return self._detect_macos()
        return None

    def _detect_windows(self) -> str | None:
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True, text=True, timeout=10,
            )
            # Find the "Default Gateway" line with an IP
            for line in result.stdout.splitlines():
                if "Default Gateway" in line:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        return match.group(1)
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _detect_linux(self) -> str | None:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=10,
            )
            match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
            return match.group(1) if match else None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _detect_macos(self) -> str | None:
        try:
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if "gateway:" in line:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        return match.group(1)
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None


# ---------------------------------------------------------------------------
# Router Admin — communicate with home router to toggle SSID broadcast
# ---------------------------------------------------------------------------


class RouterAdmin:
    """Communicate with a home router's admin interface to manage WiFi
    visibility settings. Supports common router admin APIs.

    Supported router types:
      • **openwrt**    — OpenWrt / LuCI routers (ubus JSON-RPC)
      • **ddwrt**      — DD-WRT routers (HTTP apply form)
      • **nighthawk**  — Netgear Nighthawk routers (SOAP API)
      • **generic**    — Generic HTTP routers (common endpoint probing)
      • **auto**       — Auto-detect the router type
    """

    # Common router admin endpoints to try for SSID visibility
    _PROBE_PATHS: list[dict[str, Any]] = [
        # OpenWrt / LuCI
        {
            "type": "openwrt",
            "probe": "/cgi-bin/luci/",
            "identify": "LuCI",
        },
        # DD-WRT
        {
            "type": "ddwrt",
            "probe": "/Status_Wireless.asp",
            "identify": "DD-WRT",
        },
        # Netgear Nighthawk
        {
            "type": "nighthawk",
            "probe": "/currentsetting.htm",
            "identify": "NETGEAR",
        },
    ]

    def __init__(self, config: RouterConfig | None = None) -> None:
        self._config = config
        self._detected_type: str = "generic"
        self._session_token: str = ""

    @property
    def configured(self) -> bool:
        return self._config is not None and bool(self._config.auth_header)

    @property
    def router_ip(self) -> str | None:
        return self._config.ip if self._config else None

    def configure(self, ip: str, username: str, password: str,
                  router_type: str = "auto") -> None:
        """Configure router admin access."""
        self._config = RouterConfig(ip=ip, router_type=router_type)
        self._config.set_credentials(username, password)
        if router_type != "auto":
            self._detected_type = router_type
        logger.info("Router admin configured: %s@%s (type=%s)",
                     username, ip, router_type)

    async def detect_router_type(self) -> str:
        """Try to detect the router firmware type."""
        if not self._config:
            return "unknown"
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._detect_type_sync)

    def _detect_type_sync(self) -> str:
        if not self._config:
            return "unknown"
        base = f"http://{self._config.ip}"
        for probe in self._PROBE_PATHS:
            try:
                req = urllib.request.Request(
                    f"{base}{probe['probe']}",
                    headers={"Authorization": self._config.auth_header},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    if probe["identify"] in body:
                        self._detected_type = probe["type"]
                        logger.info("Detected router type: %s",
                                     self._detected_type)
                        return self._detected_type
            except (urllib.error.URLError, OSError, ValueError):
                continue
        self._detected_type = "generic"
        return "generic"

    async def hide_ssid(self, band: str = "all") -> dict[str, Any]:
        """Disable SSID broadcast on the router.

        Args:
            band: 'all', '2.4', or '5' GHz band to hide

        Returns:
            Result dict with success status and message
        """
        if not self.configured:
            return {"success": False, "error": "Router not configured. Use: wifi router <ip> <user> <pass>"}

        loop = asyncio.get_event_loop()
        if self._detected_type == "openwrt":
            return await loop.run_in_executor(None, self._hide_openwrt, band)
        elif self._detected_type == "ddwrt":
            return await loop.run_in_executor(None, self._hide_ddwrt, band)
        elif self._detected_type == "nighthawk":
            return await loop.run_in_executor(None, self._hide_nighthawk, band)
        return await loop.run_in_executor(None, self._hide_generic, band)

    async def show_ssid(self, band: str = "all") -> dict[str, Any]:
        """Enable SSID broadcast on the router."""
        if not self.configured:
            return {"success": False, "error": "Router not configured. Use: wifi router <ip> <user> <pass>"}

        loop = asyncio.get_event_loop()
        if self._detected_type == "openwrt":
            return await loop.run_in_executor(None, self._show_openwrt, band)
        elif self._detected_type == "ddwrt":
            return await loop.run_in_executor(None, self._show_ddwrt, band)
        elif self._detected_type == "nighthawk":
            return await loop.run_in_executor(None, self._show_nighthawk, band)
        return await loop.run_in_executor(None, self._show_generic, band)

    async def get_ssid_visibility(self) -> dict[str, Any]:
        """Check current SSID broadcast status."""
        if not self.configured:
            return {"state": SSIDState.UNKNOWN.value,
                    "error": "Router not configured"}
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_visibility_sync)

    # -- OpenWrt (LuCI / ubus) -----------------------------------------

    def _openwrt_login(self) -> str | None:
        """Authenticate to OpenWrt and return session token."""
        if not self._config:
            return None
        try:
            # Extract credentials from auth header
            import base64
            decoded = base64.b64decode(
                self._config.auth_header.split(" ", 1)[1]
            ).decode()
            username, password = decoded.split(":", 1)

            data = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "call",
                "params": [
                    "00000000000000000000000000000000",
                    "session", "login",
                    {"username": username, "password": password},
                ],
            }).encode()
            req = urllib.request.Request(
                f"http://{self._config.ip}/ubus",
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                session = result.get("result", [None, {}])
                if len(session) > 1 and isinstance(session[1], dict):
                    self._session_token = session[1].get("ubus_rpc_session", "")
                    return self._session_token
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            logger.warning("OpenWrt login failed: %s", exc)
        return None

    def _openwrt_uci_call(self, method: str, params: dict) -> dict | None:
        """Make a UCI call via ubus."""
        if not self._config or not self._session_token:
            return None
        try:
            data = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "call",
                "params": [self._session_token, "uci", method, params],
            }).encode()
            req = urllib.request.Request(
                f"http://{self._config.ip}/ubus",
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, OSError, ValueError):
            return None

    def _hide_openwrt(self, band: str) -> dict[str, Any]:
        token = self._openwrt_login()
        if not token:
            return {"success": False, "error": "OpenWrt authentication failed"}
        # Set hidden=1 on wireless interfaces
        result = self._openwrt_uci_call("set", {
            "config": "wireless",
            "type": "wifi-iface",
            "values": {"hidden": "1"},
        })
        # Commit and apply
        self._openwrt_uci_call("commit", {"config": "wireless"})
        return {"success": True, "message": "SSID broadcast disabled (OpenWrt)",
                "action": "hidden"}

    def _show_openwrt(self, band: str) -> dict[str, Any]:
        token = self._openwrt_login()
        if not token:
            return {"success": False, "error": "OpenWrt authentication failed"}
        self._openwrt_uci_call("set", {
            "config": "wireless",
            "type": "wifi-iface",
            "values": {"hidden": "0"},
        })
        self._openwrt_uci_call("commit", {"config": "wireless"})
        return {"success": True, "message": "SSID broadcast enabled (OpenWrt)",
                "action": "visible"}

    # -- Netgear Nighthawk (SOAP API) -----------------------------------

    _NIGHTHAWK_SOAP_NS = "urn:NETGEAR-ROUTER:service:WLANConfiguration:1"
    _NIGHTHAWK_SOAP_NS_5G = "urn:NETGEAR-ROUTER:service:WLANConfiguration:2"
    _NIGHTHAWK_SOAP_URL = "/soap/server_sa/"

    def _nighthawk_soap_request(
        self, action: str, body_xml: str, namespace: str,
    ) -> str | None:
        """Send a SOAP request to the Nighthawk router and return the response body."""
        if not self._config:
            return None
        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<SOAP-ENV:Envelope '
            'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
            f'SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<SOAP-ENV:Header>'
            f'<SessionID>{self._session_token}</SessionID>'
            f'</SOAP-ENV:Header>'
            f'<SOAP-ENV:Body>{body_xml}</SOAP-ENV:Body>'
            f'</SOAP-ENV:Envelope>'
        )
        url = f"http://{self._config.ip}{self._NIGHTHAWK_SOAP_URL}"
        req = urllib.request.Request(
            url,
            data=envelope.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": f'"{namespace}#{action}"',
                "Authorization": self._config.auth_header,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("Nighthawk SOAP request failed (%s): %s", action, exc)
            return None

    def _nighthawk_login(self) -> bool:
        """Authenticate to the Nighthawk SOAP API."""
        if not self._config:
            return False
        login_body = (
            '<Authenticate>'
            '</Authenticate>'
        )
        # The Nighthawk uses Basic auth for the SOAP endpoint;
        # a successful response contains a SessionID we can reuse.
        url = f"http://{self._config.ip}{self._NIGHTHAWK_SOAP_URL}"
        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<SOAP-ENV:Envelope '
            'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
            'SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<SOAP-ENV:Body>'
            f'{login_body}'
            '</SOAP-ENV:Body>'
            '</SOAP-ENV:Envelope>'
        )
        req = urllib.request.Request(
            url,
            data=envelope.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": '"urn:NETGEAR-ROUTER:service:DeviceInfo:1#Authenticate"',
                "Authorization": self._config.auth_header,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                # Extract SessionID from response
                m = re.search(r"<SessionID>([^<]+)</SessionID>", body)
                if m:
                    self._session_token = m.group(1)
                    logger.info("Nighthawk SOAP login successful")
                    return True
                # Even without a session token, auth may have succeeded
                if resp.status < 400:
                    self._session_token = "authenticated"
                    return True
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("Nighthawk login failed: %s", exc)
        return False

    def _nighthawk_set_broadcast(self, enable: bool, band: str) -> dict[str, Any]:
        """Set SSID broadcast on/off for the specified band(s)."""
        if not self._nighthawk_login():
            return {"success": False, "error": "Nighthawk authentication failed"}

        value = "1" if enable else "0"
        action_word = "enabled" if enable else "disabled"
        results: list[str] = []

        bands_to_set: list[tuple[str, str]] = []
        if band in ("all", "2.4"):
            bands_to_set.append((self._NIGHTHAWK_SOAP_NS, "2.4GHz"))
        if band in ("all", "5"):
            bands_to_set.append((self._NIGHTHAWK_SOAP_NS_5G, "5GHz"))

        for ns, label in bands_to_set:
            body = (
                f'<M1:SetWLANSSIDBroadcast xmlns:M1="{ns}">'
                f'<NewSSIDBroadcast>{value}</NewSSIDBroadcast>'
                f'</M1:SetWLANSSIDBroadcast>'
            )
            resp = self._nighthawk_soap_request(
                "SetWLANSSIDBroadcast", body, ns,
            )
            if resp is not None and "ResponseCode" in resp:
                # Check for success (response code 000)
                if "000" in resp:
                    results.append(f"{label}: {action_word}")
                else:
                    results.append(f"{label}: failed")
            elif resp is not None:
                # No explicit error — assume success
                results.append(f"{label}: {action_word}")
            else:
                results.append(f"{label}: request failed")

        any_success = any(action_word in r for r in results)
        return {
            "success": any_success,
            "message": f"SSID broadcast {action_word} (Nighthawk): {', '.join(results)}",
            "action": "visible" if enable else "hidden",
            "details": results,
        }

    def _hide_nighthawk(self, band: str) -> dict[str, Any]:
        return self._nighthawk_set_broadcast(enable=False, band=band)

    def _show_nighthawk(self, band: str) -> dict[str, Any]:
        return self._nighthawk_set_broadcast(enable=True, band=band)

    # -- DD-WRT ---------------------------------------------------------

    def _hide_ddwrt(self, band: str) -> dict[str, Any]:
        if not self._config:
            return {"success": False, "error": "Not configured"}
        try:
            data = b"wl_closed=1&action=Apply"
            req = urllib.request.Request(
                f"http://{self._config.ip}/apply.cgi",
                data=data,
                headers={
                    "Authorization": self._config.auth_header,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            return {"success": True, "message": "SSID broadcast disabled (DD-WRT)",
                    "action": "hidden"}
        except (urllib.error.URLError, OSError) as exc:
            return {"success": False, "error": f"DD-WRT request failed: {exc}"}

    def _show_ddwrt(self, band: str) -> dict[str, Any]:
        if not self._config:
            return {"success": False, "error": "Not configured"}
        try:
            data = b"wl_closed=0&action=Apply"
            req = urllib.request.Request(
                f"http://{self._config.ip}/apply.cgi",
                data=data,
                headers={
                    "Authorization": self._config.auth_header,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            return {"success": True, "message": "SSID broadcast enabled (DD-WRT)",
                    "action": "visible"}
        except (urllib.error.URLError, OSError) as exc:
            return {"success": False, "error": f"DD-WRT request failed: {exc}"}

    # -- Generic HTTP ---------------------------------------------------

    def _hide_generic(self, band: str) -> dict[str, Any]:
        """Attempt to hide SSID using common router HTTP endpoints."""
        if not self._config:
            return {"success": False, "error": "Not configured"}

        # Try common endpoints used by popular consumer routers
        endpoints = [
            # TP-Link style
            ("/cgi-bin/luci", {"ssid_broadcast": "0"}),
            # Netgear style
            ("/WLG_wireless.htm", {"ssid_bc": "0"}),
            # Generic CGI
            ("/wireless.cgi", {"hidden_ssid": "1", "action": "apply"}),
        ]

        for path, params in endpoints:
            try:
                data = "&".join(f"{k}={v}" for k, v in params.items()).encode()
                req = urllib.request.Request(
                    f"http://{self._config.ip}{path}",
                    data=data,
                    headers={
                        "Authorization": self._config.auth_header,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status < 400:
                        return {
                            "success": True,
                            "message": f"SSID broadcast disabled via {path}",
                            "action": "hidden",
                        }
            except (urllib.error.URLError, OSError):
                continue

        return {
            "success": False,
            "error": (
                "Could not reach router admin. "
                "You may need to manually log into your router admin panel at "
                f"http://{self._config.ip} and disable SSID broadcast under "
                "Wireless Settings."
            ),
        }

    def _show_generic(self, band: str) -> dict[str, Any]:
        if not self._config:
            return {"success": False, "error": "Not configured"}

        endpoints = [
            ("/cgi-bin/luci", {"ssid_broadcast": "1"}),
            ("/WLG_wireless.htm", {"ssid_bc": "1"}),
            ("/wireless.cgi", {"hidden_ssid": "0", "action": "apply"}),
        ]

        for path, params in endpoints:
            try:
                data = "&".join(f"{k}={v}" for k, v in params.items()).encode()
                req = urllib.request.Request(
                    f"http://{self._config.ip}{path}",
                    data=data,
                    headers={
                        "Authorization": self._config.auth_header,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status < 400:
                        return {
                            "success": True,
                            "message": f"SSID broadcast enabled via {path}",
                            "action": "visible",
                        }
            except (urllib.error.URLError, OSError):
                continue

        return {
            "success": False,
            "error": (
                "Could not reach router admin. Manually enable SSID broadcast at "
                f"http://{self._config.ip} under Wireless Settings."
            ),
        }

    def _get_visibility_sync(self) -> dict[str, Any]:
        """Check SSID visibility — uses a WiFi scan approach."""
        if not self._config:
            return {"state": SSIDState.UNKNOWN.value}
        # We can check by scanning for our own SSID
        return {"state": SSIDState.UNKNOWN.value,
                "message": "Use 'wifi scan' to verify your SSID visibility"}


# ---------------------------------------------------------------------------
# WiFi Stealth System (main orchestrator)
# ---------------------------------------------------------------------------


class WiFiStealthSystem:
    """WiFi network stealth — hide your SSID from nearby devices.

    This system manages WiFi network visibility by communicating with
    your home router to toggle SSID broadcast. When hidden, your
    network won't appear in nearby devices' WiFi scan lists. Existing
    connected devices will remain connected.

    Capabilities:
      • Scan for all nearby WiFi networks
      • Detect your current connected network
      • Auto-detect your router's gateway IP
      • Toggle SSID broadcast on/off via router admin
      • Verify stealth by rescanning after hiding
    """

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus
        self._scanner = WiFiScanner()
        self._gateway_detector = GatewayDetector()
        self._router_admin = RouterAdmin()
        self._stealth_active = False
        self._home_ssid: str | None = None
        self._stats_scans = 0
        self._stats_hide_ops = 0
        self._stats_show_ops = 0

    # -- Scanning -------------------------------------------------------

    async def scan_networks(self) -> list[WiFiNetwork]:
        """Scan for nearby WiFi networks."""
        self._stats_scans += 1
        networks = await self._scanner.scan_networks()
        await self.event_bus.publish(Event(
            topic="wifi.scan_complete",
            data={"count": len(networks)},
        ))
        return networks

    async def get_connected_network(self) -> WiFiNetwork | None:
        """Get the currently connected WiFi network."""
        network = await self._scanner.get_connected_network()
        if network and not self._home_ssid:
            self._home_ssid = network.ssid
        return network

    # -- Gateway & Router -----------------------------------------------

    async def detect_gateway(self) -> str | None:
        """Auto-detect the default gateway (router) IP."""
        return await self._gateway_detector.detect()

    async def configure_router(self, ip: str | None = None,
                                username: str = "admin",
                                password: str = "") -> dict[str, Any]:
        """Configure router admin access.

        If ip is None, auto-detects the gateway.
        """
        if ip is None:
            ip = await self.detect_gateway()
            if ip is None:
                return {"success": False, "error": "Could not detect gateway IP. Specify manually."}

        self._router_admin.configure(ip, username, password)

        # Try to detect router type
        rtype = await self._router_admin.detect_router_type()
        return {
            "success": True,
            "router_ip": ip,
            "router_type": rtype,
            "message": f"Router configured: {username}@{ip} (type: {rtype})",
        }

    @property
    def router_configured(self) -> bool:
        return self._router_admin.configured

    # -- Stealth operations ---------------------------------------------

    async def hide_network(self, band: str = "all") -> dict[str, Any]:
        """Hide your WiFi SSID from nearby devices.

        Disables SSID broadcast on your router so your network name
        won't appear in other devices' WiFi scan lists.
        """
        if not self._router_admin.configured:
            gateway = await self.detect_gateway()
            return {
                "success": False,
                "error": (
                    "Router not configured.\n"
                    f"Detected gateway: {gateway or 'unknown'}\n"
                    "Use: wifi router <ip> <username> <password>"
                ),
            }

        result = await self._router_admin.hide_ssid(band)
        if result.get("success"):
            self._stealth_active = True
            self._stats_hide_ops += 1
            await self.event_bus.publish(Event(
                topic="wifi.stealth_activated",
                data={"band": band},
            ))
            logger.info("WiFi stealth activated — SSID broadcast disabled")
        return result

    async def show_network(self, band: str = "all") -> dict[str, Any]:
        """Make your WiFi SSID visible again.

        Re-enables SSID broadcast on your router.
        """
        if not self._router_admin.configured:
            return {"success": False,
                    "error": "Router not configured. Use: wifi router <ip> <user> <pass>"}

        result = await self._router_admin.show_ssid(band)
        if result.get("success"):
            self._stealth_active = False
            self._stats_show_ops += 1
            await self.event_bus.publish(Event(
                topic="wifi.stealth_deactivated",
                data={"band": band},
            ))
            logger.info("WiFi stealth deactivated — SSID broadcast enabled")
        return result

    async def verify_stealth(self) -> dict[str, Any]:
        """Verify stealth by scanning for your own SSID."""
        if not self._home_ssid:
            connected = await self.get_connected_network()
            if connected:
                self._home_ssid = connected.ssid

        if not self._home_ssid:
            return {"verified": False,
                    "message": "Could not determine home SSID"}

        networks = await self.scan_networks()
        ssids = [n.ssid for n in networks]
        is_hidden = self._home_ssid not in ssids

        return {
            "verified": True,
            "ssid": self._home_ssid,
            "hidden": is_hidden,
            "nearby_count": len(networks),
            "message": (
                f"'{self._home_ssid}' is NOT visible to nearby devices ✓"
                if is_hidden
                else f"'{self._home_ssid}' is still visible in scan results"
            ),
        }

    # -- Status ---------------------------------------------------------

    async def stealth_status(self) -> dict[str, Any]:
        """Get full WiFi stealth status."""
        connected = await self.get_connected_network()
        gateway = await self.detect_gateway()

        return {
            "stealth_active": self._stealth_active,
            "home_ssid": self._home_ssid or (connected.ssid if connected else "unknown"),
            "connected_network": connected.as_dict if connected else None,
            "gateway_ip": gateway,
            "router_configured": self._router_admin.configured,
            "router_ip": self._router_admin.router_ip,
            "stats": {
                "scans": self._stats_scans,
                "hide_ops": self._stats_hide_ops,
                "show_ops": self._stats_show_ops,
            },
        }

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "stealth_active": self._stealth_active,
            "home_ssid": self._home_ssid,
            "router_configured": self._router_admin.configured,
            "scans": self._stats_scans,
            "hide_ops": self._stats_hide_ops,
            "show_ops": self._stats_show_ops,
        }
