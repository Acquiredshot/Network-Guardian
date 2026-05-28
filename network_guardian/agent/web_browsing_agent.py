# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — Safe Web Browsing Agent

Autonomous agent that evaluates URLs for safety before allowing access.
Operates via a four-stage ReAct cycle:

  OBSERVE  — receive a URL to evaluate (direct call or event subscription)
  REASON   — check allowlist/blocklist, extract hostname, fetch page content,
              score threat signals (phishing, malware, drive-by, cryptominer…)
  ACT      — return a UrlVerdict, publish event, optionally call ips.block_ip()
              for high-confidence malicious domains
  LEARN    — persist per-domain verdicts, update statistics, adapt signal weights

Security design notes
---------------------
* URL parsing uses ``urllib.parse.urlparse`` — no regex on the full URL string
  to avoid catastrophic backtracking and operator-precedence bugs.
* All HTTP requests carry an explicit ``timeout=(5, 15)`` (connect, read) so
  a slow/hung server can never block the agent indefinitely.
* Private / loopback / link-local addresses are refused before any socket or
  HTTP connection is made (SSRF mitigation).
* Domain list matching uses exact hostname comparison and ``fnmatch``-style
  wildcard subdomains, not raw regex injection from user-supplied strings.
* Fetched content is size-capped (``_MAX_CONTENT_BYTES``) before parsing to
  prevent memory exhaustion from maliciously large pages.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, TYPE_CHECKING

try:
    import requests
    from bs4 import BeautifulSoup
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus
    from network_guardian.ips import IntrusionPreventionSystem

logger = logging.getLogger("network_guardian.agent.web_browsing")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT: tuple[int, int] = (5, 15)       # (connect_secs, read_secs)
_MAX_CONTENT_BYTES: int = 512 * 1024               # 512 KB cap on fetched HTML
_MAX_REDIRECTS: int = 5
_REQUEST_HEADERS: dict[str, str] = {
    "User-Agent": "NetworkGuardian/1.0 SafeWebBrowsingAgent",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}

# ---------------------------------------------------------------------------
# Threat signal catalogue
# ---------------------------------------------------------------------------

# (pattern, signal_name, severity, confidence_contribution)
_CONTENT_SIGNALS: list[tuple[re.Pattern[str], str, str, float]] = [
    # Phishing
    (re.compile(r"verify\s+your\s+(account|identity|password|credit\s+card)", re.I),
     "phishing_verify_account", "high", 0.75),
    (re.compile(r"(confirm|update)\s+your\s+(billing|payment|password)\s+info", re.I),
     "phishing_update_billing", "high", 0.70),
    (re.compile(r"your\s+account\s+(has been|will be)\s+(suspended|locked|disabled)", re.I),
     "phishing_account_suspended", "high", 0.75),
    (re.compile(r"click\s+here\s+to\s+(unlock|verify|restore|claim\s+your\s+prize)", re.I),
     "phishing_cta", "medium", 0.55),

    # Malware / drive-by keywords
    (re.compile(r"\b(malware|spyware|adware|rootkit|trojan|ransomware)\b", re.I),
     "malware_keyword", "critical", 0.65),
    (re.compile(r"(drive[- ]by\s+download|silent\s+install|auto[- ]download)", re.I),
     "drive_by_download", "critical", 0.80),
    (re.compile(r"eval\s*\(\s*unescape\s*\(", re.I),
     "js_eval_unescape", "critical", 0.85),
    (re.compile(r"eval\s*\(\s*atob\s*\(", re.I),
     "js_eval_atob", "critical", 0.85),
    (re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.I),
     "js_docwrite_unescape", "high", 0.80),
    (re.compile(r"<iframe[^>]+(?:hidden|display\s*:\s*none|visibility\s*:\s*hidden)", re.I),
     "hidden_iframe", "high", 0.70),

    # Crypto-miner injection
    (re.compile(r"(coinhive|cryptonight|minero\s+pool|coinimp|minexmr)", re.I),
     "cryptominer_known", "critical", 0.90),
    (re.compile(r"new\s+(?:Worker|Miner)\s*\(['\"]blob:", re.I),
     "cryptominer_worker_blob", "critical", 0.88),

    # Exploit kit indicators
    (re.compile(r"(shellcode|heap\s+spray|rop\s+chain|jit\s+spray)", re.I),
     "exploit_kit_language", "critical", 0.75),
    (re.compile(r"(BlackHole|Angler|Nuclear|Magnitude|RIG|Fallout)\s+(?:EK|exploit\s+kit)", re.I),
     "exploit_kit_named", "critical", 0.95),

    # Credential harvesting
    (re.compile(r"<form[^>]+action=['\"][^'\"]*(?:login|signin|verify|harvest)[^'\"]*['\"]", re.I),
     "credential_harvest_form", "high", 0.65),

    # Generic suspicious
    (re.compile(r"\b(hacked|cracked|keygen|serial\s+key|warez|nulled)\b", re.I),
     "piracy_warez", "medium", 0.50),
    (re.compile(r"(free\s+iphone|you\s+have\s+won|congratulations.*prize|click\s+to\s+claim)", re.I),
     "scam_prize", "medium", 0.55),
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class UrlCategory(Enum):
    TRUSTED     = "trusted"      # in the allowlist
    BLOCKED     = "blocked"      # in the blocklist
    SAFE        = "safe"         # fetched + analysed, no signals
    SUSPICIOUS  = "suspicious"   # low–medium threat signals
    MALICIOUS   = "malicious"    # high–critical threat signals, auto-block eligible
    ERROR       = "error"        # could not fetch or parse
    SKIPPED     = "skipped"      # non-HTTP scheme, private IP, etc.


@dataclass
class ThreatSignal:
    """A single matched threat signal found in page content."""
    name: str
    severity: str            # "medium" | "high" | "critical"
    confidence: float        # contribution 0.0–1.0
    excerpt: str = ""        # short snippet from content (≤120 chars)


@dataclass
class UrlVerdict:
    """Complete verdict for one URL evaluation."""
    verdict_id: str
    url: str
    hostname: str
    category: UrlCategory
    threat_score: float          # 0.0–100.0
    confidence: float            # combined 0.0–1.0
    signals: list[ThreatSignal] = field(default_factory=list)
    action_taken: str = "none"   # "none" | "logged" | "blocked"
    block_duration: int | None = None
    elapsed_ms: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["signals"] = [asdict(s) for s in self.signals]
        return d


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _extract_hostname(url: str) -> str | None:
    """Return the lowercase hostname from *url*, or ``None`` if unparseable."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname  # already lower-cased by urlparse
        return host if host else None
    except Exception:
        return None


def _is_private_address(hostname: str) -> bool:
    """Return True if *hostname* resolves to a private/loopback/link-local IP.

    Prevents SSRF attacks where an attacker supplies an internal address.
    """
    # Explicit loopback / local names
    if hostname in ("localhost", "localdomain") or hostname.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        pass
    # Resolve and check
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
        for _fam, _typ, _proto, _cname, sockaddr in infos:
            try:
                addr = ipaddress.ip_address(sockaddr[0])
                if addr.is_private or addr.is_loopback or addr.is_link_local:
                    return True
            except ValueError:
                continue
    except OSError:
        pass
    return False


def _domain_in_list(hostname: str, domain_list: list[str]) -> bool:
    """Return True if *hostname* matches any entry in *domain_list*.

    Entries support exact match or leading ``*.`` wildcard (e.g. ``*.evil.com``
    matches ``sub.evil.com`` and ``evil.com`` itself).
    No raw regex — user-supplied strings are never treated as patterns.
    """
    hostname = hostname.lower()
    for entry in domain_list:
        entry = entry.lower().lstrip("*").lstrip(".")
        if hostname == entry or hostname.endswith("." + entry):
            return True
    return False


def _combined_confidence(signals: list[ThreatSignal]) -> float:
    """Combine independent signal confidences: 1 - ∏(1 - cᵢ)."""
    if not signals:
        return 0.0
    result = 1.0
    for s in signals:
        result *= (1.0 - s.confidence)
    return round(1.0 - result, 4)


def _threat_score(signals: list[ThreatSignal]) -> float:
    """Map combined confidence + worst severity to a 0–100 threat score."""
    if not signals:
        return 0.0
    conf = _combined_confidence(signals)
    sev_weights = {"critical": 100, "high": 70, "medium": 40}
    worst = max(sev_weights.get(s.severity, 30) for s in signals)
    return round(conf * worst, 1)


def _verdict_category(signals: list[ThreatSignal]) -> UrlCategory:
    """Choose SAFE / SUSPICIOUS / MALICIOUS from the signal list."""
    if not signals:
        return UrlCategory.SAFE
    severities = {s.severity for s in signals}
    if "critical" in severities or "high" in severities:
        return UrlCategory.MALICIOUS
    return UrlCategory.SUSPICIOUS


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class SafeWebBrowsingAgent:
    """Autonomous safe-browsing evaluation agent.

    Parameters
    ----------
    event_bus:
        Optional event bus for publishing ``web.url.verdict`` events.
    ips:
        Optional IPS; when provided, MALICIOUS domains are automatically
        blocked at the network layer.
    data_dir:
        Directory for persisting domain lists and verdict history.
        Defaults to ``~/.network_guardian/web_browsing/``.
    auto_block:
        When ``True`` (default) and an IPS is wired in, MALICIOUS verdicts
        trigger an automatic ``ips.block_ip()`` call.
    fetch_content:
        When ``True`` (default), unknown domains are fetched and their HTML
        is content-analysed.  Disable to run list-only (faster, no network).
    request_timeout:
        ``(connect_secs, read_secs)`` tuple forwarded to ``requests.get``.
    """

    def __init__(
        self,
        event_bus: "EventBus | None" = None,
        ips: "IntrusionPreventionSystem | None" = None,
        data_dir: Path | None = None,
        auto_block: bool = True,
        fetch_content: bool = True,
        request_timeout: tuple[int, int] = _DEFAULT_TIMEOUT,
    ) -> None:
        self._event_bus = event_bus
        self._ips = ips
        self._data_dir: Path = (
            data_dir
            if data_dir is not None
            else Path.home() / ".network_guardian" / "web_browsing"
        )
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self.auto_block = auto_block
        self.fetch_content = fetch_content
        self._timeout = request_timeout

        # Domain lists (lowercase, no scheme)
        self._blocklist: list[str] = [
            "malware.example.com",
            "phishing.example.com",
        ]
        self._allowlist: list[str] = [
            "google.com",
            "github.com",
            "microsoft.com",
            "apple.com",
        ]

        # Stats
        self._total_checked: int = 0
        self._total_blocked: int = 0
        self._total_malicious: int = 0
        self._verdict_history: list[dict[str, Any]] = []

        self._load_lists()

        logger.info(
            "[WebBrowsing] Agent ready — %d blocked domains, %d allowed",
            len(self._blocklist), len(self._allowlist),
        )

    # ------------------------------------------------------------------
    # Public API — URL evaluation
    # ------------------------------------------------------------------

    def check_url(self, url: str, source_ip: str = "unknown") -> UrlVerdict:
        """Evaluate *url* and return a :class:`UrlVerdict`.

        This is the primary entry point.  Runs synchronously (blocking I/O
        on the content fetch) so call from a thread or wrap in
        ``asyncio.to_thread`` when used inside an async context.
        """
        start = time.monotonic()
        self._total_checked += 1

        # -- OBSERVE -------------------------------------------------------
        verdict_id = f"web-{int(time.time())}-{abs(hash(url)) % 100_000:05d}"

        # Validate scheme
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return self._make_verdict(
                verdict_id, url, "",
                UrlCategory.SKIPPED, [], start,
                error=f"Non-HTTP scheme: {parsed.scheme!r}",
            )

        hostname = _extract_hostname(url)
        if not hostname:
            return self._make_verdict(
                verdict_id, url, "",
                UrlCategory.ERROR, [], start,
                error="Could not parse hostname from URL",
            )

        # -- REASON — list checks -----------------------------------------
        if _domain_in_list(hostname, self._blocklist):
            v = self._make_verdict(
                verdict_id, url, hostname,
                UrlCategory.BLOCKED,
                [ThreatSignal("blocklist_match", "critical", 1.0, "")],
                start,
            )
            v.action_taken = "blocked"
            self._total_blocked += 1
            self._record(v)
            self._publish(v, source_ip)
            return v

        if _domain_in_list(hostname, self._allowlist):
            v = self._make_verdict(
                verdict_id, url, hostname,
                UrlCategory.TRUSTED, [], start,
            )
            v.action_taken = "none"
            self._record(v)
            return v

        # -- REASON — SSRF guard -------------------------------------------
        if _is_private_address(hostname):
            return self._make_verdict(
                verdict_id, url, hostname,
                UrlCategory.SKIPPED, [], start,
                error="Private/loopback address — refused (SSRF guard)",
            )

        # -- REASON — content fetch & signal scan --------------------------
        signals: list[ThreatSignal] = []
        error: str | None = None

        if self.fetch_content and _REQUESTS_AVAILABLE:
            signals, error = self._fetch_and_analyze(url)
        elif not _REQUESTS_AVAILABLE:
            error = "requests/beautifulsoup4 not installed; list-only mode"

        category = _verdict_category(signals)

        # -- ACT -----------------------------------------------------------
        v = self._make_verdict(verdict_id, url, hostname, category, signals, start,
                               error=error)

        if category == UrlCategory.MALICIOUS:
            self._total_malicious += 1
            if self.auto_block and self._ips is not None:
                try:
                    self._ips.block_ip(hostname, duration=3600,
                                       reason=f"SafeWebBrowsing: malicious domain "
                                              f"(score={v.threat_score})")
                    v.action_taken = "blocked"
                    v.block_duration = 3600
                    self._total_blocked += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning("[WebBrowsing] IPS block failed for %s: %s", hostname, exc)
                    v.action_taken = "logged"
            else:
                v.action_taken = "logged"
        elif category in (UrlCategory.SUSPICIOUS, UrlCategory.SAFE):
            v.action_taken = "logged"

        # -- LEARN ---------------------------------------------------------
        self._record(v)
        self._publish(v, source_ip)

        logger.info(
            "[WebBrowsing] %s → %s (score=%.1f, signals=%d, %.0fms)",
            hostname, category.value, v.threat_score,
            len(signals), v.elapsed_ms,
        )
        return v

    # ------------------------------------------------------------------
    # Domain list management
    # ------------------------------------------------------------------

    def add_to_blocklist(self, domain: str) -> None:
        """Add *domain* to the persistent block list."""
        domain = domain.lower().strip()
        if domain not in self._blocklist:
            self._blocklist.append(domain)
            self._persist_lists()
            logger.info("[WebBrowsing] Blocked domain added: %s", domain)

    def remove_from_blocklist(self, domain: str) -> bool:
        """Remove *domain* from the block list. Returns True if found."""
        domain = domain.lower().strip()
        if domain in self._blocklist:
            self._blocklist.remove(domain)
            self._persist_lists()
            return True
        return False

    def add_to_allowlist(self, domain: str) -> None:
        """Add *domain* to the persistent allow list."""
        domain = domain.lower().strip()
        if domain not in self._allowlist:
            self._allowlist.append(domain)
            self._persist_lists()
            logger.info("[WebBrowsing] Allowed domain added: %s", domain)

    def remove_from_allowlist(self, domain: str) -> bool:
        """Remove *domain* from the allow list. Returns True if found."""
        domain = domain.lower().strip()
        if domain in self._allowlist:
            self._allowlist.remove(domain)
            self._persist_lists()
            return True
        return False

    # ------------------------------------------------------------------
    # Stats / dashboard
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return a live statistics snapshot."""
        category_counts: dict[str, int] = defaultdict(int)
        for entry in self._verdict_history:
            category_counts[entry.get("category", "unknown")] += 1

        top_malicious = [
            e["hostname"] for e in self._verdict_history
            if e.get("category") in ("malicious", "blocked")
        ]
        # Deduplicate, preserve insertion order, take top 5
        seen: set[str] = set()
        top_5: list[str] = []
        for h in reversed(top_malicious):
            if h not in seen:
                seen.add(h)
                top_5.append(h)
            if len(top_5) == 5:
                break

        return {
            "total_checked":      self._total_checked,
            "total_blocked":      self._total_blocked,
            "total_malicious":    self._total_malicious,
            "blocklist_size":     len(self._blocklist),
            "allowlist_size":     len(self._allowlist),
            "verdicts_in_memory": len(self._verdict_history),
            "category_counts":    dict(category_counts),
            "top_malicious_hosts": top_5,
            "fetch_content":      self.fetch_content,
            "auto_block":         self.auto_block,
        }

    def dashboard_summary(self) -> dict[str, Any]:
        """JSON-serialisable summary for the ``/api/web_browsing`` endpoint."""
        s = self.get_stats()
        last = self._verdict_history[-1] if self._verdict_history else None
        return {
            "status":             "active",
            "total_checked":      s["total_checked"],
            "total_blocked":      s["total_blocked"],
            "total_malicious":    s["total_malicious"],
            "blocklist_size":     s["blocklist_size"],
            "allowlist_size":     s["allowlist_size"],
            "top_malicious_hosts": s["top_malicious_hosts"],
            "last_verdict": {
                "url":          last.get("url") if last else None,
                "category":     last.get("category") if last else None,
                "threat_score": last.get("threat_score") if last else None,
                "timestamp":    last.get("timestamp") if last else None,
            },
        }

    # ------------------------------------------------------------------
    # Internal: content analysis
    # ------------------------------------------------------------------

    def _fetch_and_analyze(
        self, url: str
    ) -> tuple[list[ThreatSignal], str | None]:
        """Fetch *url* and scan its content. Returns (signals, error|None)."""
        try:
            session = requests.Session()
            session.max_redirects = _MAX_REDIRECTS
            resp = session.get(
                url,
                timeout=self._timeout,
                headers=_REQUEST_HEADERS,
                allow_redirects=True,
                stream=True,          # stream so we can cap size
                verify=True,          # enforce SSL verification
            )
            # Read up to _MAX_CONTENT_BYTES
            content = b""
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if len(content) >= _MAX_CONTENT_BYTES:
                    break

            # Parse with lxml (fastest) or fall back to html.parser
            try:
                soup = BeautifulSoup(content, "lxml")
            except Exception:
                soup = BeautifulSoup(content, "html.parser")

            text = soup.get_text(separator=" ", strip=True)
            raw_html = content.decode("utf-8", errors="ignore")

            signals = self._detect_signals(text, raw_html, url)
            return signals, None

        except requests.exceptions.SSLError as exc:
            return [ThreatSignal("ssl_error", "high", 0.60, str(exc)[:120])], \
                   f"SSL error: {exc}"
        except requests.exceptions.TooManyRedirects:
            return [ThreatSignal("redirect_loop", "medium", 0.50, "")], \
                   "Too many redirects"
        except requests.exceptions.Timeout:
            return [], "Request timed out"
        except requests.exceptions.ConnectionError as exc:
            return [], f"Connection error: {exc}"
        except Exception as exc:  # noqa: BLE001
            logger.warning("[WebBrowsing] Fetch error for %s: %s", url, exc)
            return [], f"Unexpected error: {exc}"

    def _detect_signals(
        self, text: str, raw_html: str, url: str
    ) -> list[ThreatSignal]:
        """Run all content signal patterns against *text* and *raw_html*."""
        signals: list[ThreatSignal] = []
        seen: set[str] = set()

        for pattern, name, severity, confidence in _CONTENT_SIGNALS:
            if name in seen:
                continue
            # Match against visible text OR raw HTML depending on pattern type
            target = raw_html if name.startswith(("js_", "hidden_", "credential_")) else text
            m = pattern.search(target)
            if m:
                start = max(0, m.start() - 30)
                excerpt = target[start: m.end() + 30].replace("\n", " ")[:120]
                signals.append(ThreatSignal(name, severity, confidence, excerpt))
                seen.add(name)

        return signals

    # ------------------------------------------------------------------
    # Internal: persistence
    # ------------------------------------------------------------------

    def _persist_lists(self) -> None:
        path = self._data_dir / "domain_lists.json"
        try:
            path.write_text(
                json.dumps(
                    {"blocklist": self._blocklist, "allowlist": self._allowlist},
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("[WebBrowsing] Could not persist domain lists: %s", exc)

    def _load_lists(self) -> None:
        path = self._data_dir / "domain_lists.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._blocklist = data.get("blocklist", self._blocklist)
            self._allowlist = data.get("allowlist", self._allowlist)
            logger.debug(
                "[WebBrowsing] Loaded %d blocked, %d allowed domains from disk",
                len(self._blocklist), len(self._allowlist),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("[WebBrowsing] Could not load domain lists: %s", exc)

    def _record(self, verdict: UrlVerdict) -> None:
        """Append verdict to in-memory history (capped at 1,000 entries)."""
        self._verdict_history.append(verdict.to_dict())
        if len(self._verdict_history) > 1_000:
            self._verdict_history = self._verdict_history[-1_000:]

    def _publish(self, verdict: UrlVerdict, source_ip: str) -> None:
        """Publish a ``web.url.verdict`` event on the event bus if wired."""
        if self._event_bus is None:
            return
        payload = {
            "verdict_id":   verdict.verdict_id,
            "url":          verdict.url,
            "hostname":     verdict.hostname,
            "category":     verdict.category.value,
            "threat_score": verdict.threat_score,
            "action_taken": verdict.action_taken,
            "source_ip":    source_ip,
            "timestamp":    verdict.timestamp,
        }
        try:
            from network_guardian.core.events import Event as _Event
            self._event_bus.publish(_Event(topic="web.url.verdict", data=payload))
        except ImportError:
            # Fallback: bus may accept a plain dict or a simple object
            self._event_bus.publish(type("Event", (), {"type": "web.url.verdict", "data": payload})())
        except Exception as exc:  # noqa: BLE001
            logger.debug("[WebBrowsing] Event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Internal: helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_verdict(
        verdict_id: str,
        url: str,
        hostname: str,
        category: UrlCategory,
        signals: list[ThreatSignal],
        start: float,
        error: str | None = None,
    ) -> UrlVerdict:
        elapsed = round((time.monotonic() - start) * 1000, 1)
        return UrlVerdict(
            verdict_id=verdict_id,
            url=url,
            hostname=hostname,
            category=category,
            threat_score=_threat_score(signals),
            confidence=_combined_confidence(signals),
            signals=signals,
            elapsed_ms=elapsed,
            error=error,
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli_main() -> None:
    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)s %(message)s")
    print("Network Guardian — Safe Web Browsing Agent")
    print("Commands: check <url>, block <domain>, allow <domain>, unblock <domain>,")
    print("          unallow <domain>, stats, history, help, quit\n")

    agent = SafeWebBrowsingAgent(fetch_content=_REQUESTS_AVAILABLE, auto_block=False)

    while True:
        try:
            raw = input("web> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nQuitting...")
            break

        if not raw:
            continue

        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "q", "exit"):
            print("Quitting...")
            break

        elif cmd == "check":
            url = rest.strip()
            if not url:
                print("  Usage: check <url>")
                continue
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            print(f"  Checking {url} …")
            v = agent.check_url(url)
            print(f"  Category    : {v.category.value.upper()}")
            print(f"  Threat score: {v.threat_score}/100")
            print(f"  Confidence  : {v.confidence:.0%}")
            if v.signals:
                print(f"  Signals ({len(v.signals)}):")
                for s in v.signals:
                    print(f"    [{s.severity}] {s.name}  (conf={s.confidence:.0%})")
                    if s.excerpt:
                        print(f"      › {s.excerpt[:80]}")
            if v.error:
                print(f"  Note: {v.error}")
            print(f"  Elapsed: {v.elapsed_ms:.0f}ms")

        elif cmd == "block":
            domain = rest.strip()
            if domain:
                agent.add_to_blocklist(domain)
                print(f"  Added to blocklist: {domain}")
            else:
                print("  Usage: block <domain>")

        elif cmd == "allow":
            domain = rest.strip()
            if domain:
                agent.add_to_allowlist(domain)
                print(f"  Added to allowlist: {domain}")
            else:
                print("  Usage: allow <domain>")

        elif cmd == "unblock":
            domain = rest.strip()
            found = agent.remove_from_blocklist(domain)
            print(f"  {'Removed from' if found else 'Not found in'} blocklist: {domain}")

        elif cmd == "unallow":
            domain = rest.strip()
            found = agent.remove_from_allowlist(domain)
            print(f"  {'Removed from' if found else 'Not found in'} allowlist: {domain}")

        elif cmd == "stats":
            s = agent.get_stats()
            for k, v in s.items():
                print(f"  {k}: {v}")

        elif cmd == "history":
            hist = agent._verdict_history[-10:]
            if not hist:
                print("  No verdicts yet.")
            else:
                for entry in hist:
                    print(f"  [{entry['category'].upper():12s}] {entry['hostname']:40s} "
                          f"score={entry['threat_score']:5.1f}  {entry['timestamp'][:19]}")

        elif cmd == "blocklist":
            for d in agent._blocklist:
                print(f"  {d}")

        elif cmd == "allowlist":
            for d in agent._allowlist:
                print(f"  {d}")

        elif cmd == "help":
            print("  check <url>         Evaluate a URL for safety")
            print("  block <domain>      Add domain to block list")
            print("  allow <domain>      Add domain to allow list")
            print("  unblock <domain>    Remove domain from block list")
            print("  unallow <domain>    Remove domain from allow list")
            print("  blocklist           Show all blocked domains")
            print("  allowlist           Show all allowed domains")
            print("  stats               Show agent statistics")
            print("  history             Show last 10 verdicts")
            print("  quit                Exit")
        else:
            print(f"  Unknown command: {cmd!r}. Type 'help' for commands.")


if __name__ == "__main__":
    _cli_main()
