#!/usr/bin/env python3
"""
Network Guardian — Field Agent (Probe)

Self-contained agent that scans the local network, collects system metrics,
and reports back to the Wolfpak base station.  Zero external dependencies
beyond the Python 3.11+ stdlib so it can be frozen with PyInstaller.

Usage (standalone):
    python probe.py --base http://192.168.1.100:8080 --key <agent-key>

Usage (packaged executable):
    ./ng-probe --base http://192.168.1.100:8080 --key <agent-key>

The agent:
  1. Identifies itself (unique agent ID, hostname, platform)
  2. Scans WiFi networks
  3. Discovers live hosts via ICMP / ARP
  4. Collects system metrics (CPU, disk, memory)
  5. Phones home every <interval> seconds with a JSON report
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from network_guardian.agent.covert_comms import CovertComms, build_comms
from network_guardian.agent.threat_analyzer import ProbeThrottleAnalyzer, ThreatAlert

logger = logging.getLogger("ng-probe")

_AGENT_DIR = Path.home() / ".ng_agent"

# ---------------------------------------------------------------------------
# Wolfpak team authentication (required for agent activation)
# ---------------------------------------------------------------------------

_AUTH_FILE = "wolfpak_auth.json"
_TOKEN_LIFETIME = 30 * 86400  # 30 days before re-auth required


def _auth_path() -> Path:
    return _AGENT_DIR / _AUTH_FILE


def _load_auth_token() -> dict | None:
    """Load saved auth token. Returns dict with token + metadata or None."""
    p = _auth_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        if time.time() - data.get("authenticated_at", 0) > _TOKEN_LIFETIME:
            logger.warning("Auth token expired — re-authentication required")
            p.unlink(missing_ok=True)
            return None
        return data
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def _save_auth_token(token_data: dict) -> None:
    """Persist auth token to disk (readable only by owner)."""
    p = _auth_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(token_data, indent=2))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def authenticate_agent(base_url: str, fleet_key: str,
                        username: str | None = None,
                        password: str | None = None) -> dict:
    """Authenticate with the Wolfpak base station.

    On first run (or token expiry), requires username + password.
    On subsequent runs, uses the cached auth token.
    Returns auth dict with 'operator', 'agent_token', 'authenticated_at'.
    Raises SystemExit on failure.
    """
    # Check cached token first
    cached = _load_auth_token()
    if cached:
        logger.info("Authenticated as %s (cached token, %dd remaining)",
                     cached.get("operator", "?"),
                     max(0, int((_TOKEN_LIFETIME - (time.time() - cached.get("authenticated_at", 0))) / 86400)))
        return cached

    # Need fresh credentials
    if not username or not password:
        # Interactive prompt
        print("\n" + "=" * 50)
        print("  WOLFPAK AUTHENTICATION REQUIRED")
        print("  Only authorized Wolfpak members can use this agent.")
        print("=" * 50)
        try:
            import getpass
            username = input("  Username: ").strip()
            password = getpass.getpass("  Password: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Authentication cancelled.")
            sys.exit(1)

    if not username or not password:
        print("  ERROR: Username and password are required.")
        sys.exit(1)

    # Verify against base station
    url = f"{base_url.rstrip('/')}/api/fleet/auth"
    payload = json.dumps({
        "username": username,
        "password": password,
    }).encode()
    sig = hmac.new(fleet_key.encode(), payload, hashlib.sha256).hexdigest()

    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-Agent-Signature": sig,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("\n  ACCESS DENIED — Invalid credentials or unauthorized.")
            print("  Contact your Wolfpak administrator.")
            sys.exit(1)
        print(f"\n  Authentication failed: HTTP {e.code}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  Cannot reach base station: {e}")
        sys.exit(1)

    if not body.get("ok"):
        print(f"\n  ACCESS DENIED — {body.get('message', 'Unknown error')}")
        sys.exit(1)

    # Save token
    token_data = {
        "operator": body.get("operator", username),
        "agent_token": body.get("agent_token", ""),
        "role": body.get("role", "operator"),
        "authenticated_at": int(time.time()),
        "base_url": base_url,
    }
    _save_auth_token(token_data)
    print(f"\n  ACCESS GRANTED — Welcome, {token_data['operator']}.")
    print(f"  Token valid for {_TOKEN_LIFETIME // 86400} days.\n")
    logger.info("Wolfpak auth successful for %s", token_data["operator"])
    return token_data


def deauth_agent() -> None:
    """Remove stored auth token (logout)."""
    p = _auth_path()
    if p.exists():
        p.unlink()
        print("  Agent deauthenticated. Wolfpak credentials required on next run.")
    else:
        print("  No active authentication found.")


# ---------------------------------------------------------------------------
# Agent identity
# ---------------------------------------------------------------------------

_ID_FILE = ".ng_agent_id"


def _get_or_create_id(data_dir: Path) -> str:
    """Return a persistent agent ID, creating one on first run."""
    path = data_dir / _ID_FILE
    if path.exists():
        return path.read_text().strip()
    agent_id = f"NG-{secrets.token_hex(4).upper()}"
    data_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(agent_id)
    return agent_id


@dataclass
class AgentIdentity:
    agent_id: str
    hostname: str = ""
    platform_os: str = ""
    arch: str = ""
    python_ver: str = ""
    mac_addr: str = ""

    @classmethod
    def collect(cls, data_dir: Path) -> AgentIdentity:
        import uuid
        mac = ":".join(f"{b:02x}" for b in uuid.getnode().to_bytes(6, "big"))
        return cls(
            agent_id=_get_or_create_id(data_dir),
            hostname=socket.gethostname(),
            platform_os=f"{platform.system()} {platform.release()}",
            arch=platform.machine(),
            python_ver=platform.python_version(),
            mac_addr=mac,
        )


# ---------------------------------------------------------------------------
# WiFi scanner (same logic as main system, embedded for portability)
# ---------------------------------------------------------------------------

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str = ""
    signal: int = 0
    channel: int = 0
    security: str = "Unknown"
    frequency: str = ""
    hidden: bool = False


def _normalise_security(raw: str) -> str:
    """Convert macOS internal security key strings to readable names."""
    if not raw or raw in ("None", "none"):
        return "Open"
    r = raw.lower()
    if "wpa3" in r:
        return "WPA3"
    if "wpa2" in r or "rsn" in r:
        return "WPA2"
    if "wpa" in r:
        return "WPA"
    if "wep" in r:
        return "WEP"
    if "open" in r:
        return "Open"
    # If it looks like a readable string already, return as-is
    if raw in ("WPA3", "WPA2", "WPA", "WEP", "Open", "Unknown"):
        return raw
    # Last resort — strip macOS prefix
    cleaned = raw.replace("spairport_security_mode_", "").replace("_", " ").upper()
    return cleaned if cleaned else "Unknown"


def _airport_scan_macos() -> list[dict[str, Any]]:
    """Fallback: use the legacy airport binary to scan WiFi on macOS."""
    airport = (
        "/System/Library/PrivateFrameworks/Apple80211.framework"
        "/Versions/Current/Resources/airport"
    )
    if not Path(airport).exists():
        return []
    try:
        r = subprocess.run([airport, "-s"], capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    networks: list[dict[str, Any]] = []
    for line in r.stdout.splitlines()[1:]:  # skip header
        line = line.strip()
        if not line:
            continue
        # Format: SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
        parts = line.rsplit(None, 6)
        if len(parts) < 7:
            parts = line.split()
            if len(parts) < 2:
                continue
            ssid = parts[0]
            bssid = parts[1] if len(parts) > 1 else ""
            rssi = int(parts[2]) if len(parts) > 2 and parts[2].lstrip("-").isdigit() else 0
            channel = int(parts[3].split(",")[0]) if len(parts) > 3 else 0
            security = " ".join(parts[6:]) if len(parts) > 6 else "Unknown"
        else:
            # ssid may have spaces; BSSID is aa:bb:cc:dd:ee:ff pattern
            import re as _re
            m = _re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', line, _re.I)
            if not m:
                continue
            bssid_pos = m.start()
            ssid = line[:bssid_pos].strip()
            tail = line[bssid_pos:].split()
            bssid = tail[0] if tail else ""
            rssi = int(tail[1]) if len(tail) > 1 and tail[1].lstrip("-").isdigit() else 0
            ch_raw = tail[2] if len(tail) > 2 else "0"
            channel = int(ch_raw.split(",")[0]) if ch_raw.split(",")[0].isdigit() else 0
            security = " ".join(tail[5:]) if len(tail) > 5 else "Unknown"
        if not ssid:
            continue
        networks.append({
            "ssid": ssid,
            "bssid": bssid,
            "signal": rssi,
            "channel": channel,
            "frequency": "5 GHz" if channel > 14 else "2.4 GHz",
            "security": _normalise_security(security),
            "hidden": False,
            "connected": False,
        })
    return networks


def scan_wifi() -> list[dict[str, Any]]:
    """Scan for nearby WiFi networks. Returns list of dicts."""
    os_name = platform.system().lower()
    try:
        if os_name == "darwin":
            return _scan_macos()
        elif os_name == "linux":
            return _scan_linux()
        elif os_name == "windows":
            return _scan_windows()
    except Exception as exc:
        logger.warning("WiFi scan failed: %s", exc)
    return []


def _scan_macos() -> list[dict[str, Any]]:
    r = subprocess.run(
        ["system_profiler", "SPAirPortDataType", "-json"],
        capture_output=True, text=True, timeout=20,
    )
    networks: list[dict[str, Any]] = []
    try:
        data = json.loads(r.stdout)
        # Primary path: spairport_airport_interfaces (works on macOS 14+)
        interfaces = (
            data.get("SPAirPortDataType", [{}])[0]
                .get("spairport_airport_interfaces", [])
        )
        for iface in interfaces:
            other = iface.get("spairport_airport_other_local_wireless_networks", [])
            current = iface.get("spairport_current_network_information", {})
            connected_ssid = current.get("_name", "") if current else ""
            all_nets = ([current] if current else []) + other
            for net in all_nets:
                ssid = net.get("_name", "")
                rssi_raw = net.get("spairport_network_signal_noise", "")
                rssi = rssi_raw.split("/")[0].strip() if rssi_raw else ""
                channel = _parse_channel(net.get("spairport_network_channel", ""))
                security_raw = net.get("spairport_security_mode", "Unknown")
                networks.append({
                    "ssid": ssid,
                    "bssid": net.get("spairport_network_bssid", ""),
                    "signal": int(rssi) if rssi.lstrip("-").isdigit() else 0,
                    "channel": channel,
                    "frequency": "5 GHz" if channel > 14 else "2.4 GHz",
                    "security": _normalise_security(security_raw),
                    "hidden": not bool(ssid),
                    "connected": bool(ssid and ssid == connected_ssid),
                })
        # Fallback: older macOS format with nested interface dicts
        if not networks:
            items = data.get("SPAirPortDataType", [])
            for item in items:
                for iface_key, iface_data in item.items():
                    if not isinstance(iface_data, dict):
                        continue
                    other = iface_data.get("spairport_airport_other_local_wireless_networks", [])
                    if isinstance(other, list):
                        for net in other:
                            if isinstance(net, dict):
                                name = net.get("_name", "")
                                channel = _parse_channel(net.get("spairport_network_channel", ""))
                                networks.append({
                                    "ssid": name,
                                    "bssid": net.get("spairport_network_bssid", ""),
                                    "signal": _parse_signal(net.get("spairport_signal_noise", "")),
                                    "channel": channel,
                                    "frequency": "5 GHz" if channel > 14 else "2.4 GHz",
                                    "security": _normalise_security(net.get("spairport_security_mode", "Unknown")),
                                    "hidden": not bool(name),
                                    "connected": False,
                                })
    except (json.JSONDecodeError, KeyError, TypeError, IndexError):
        pass
    # Strip macOS privacy-redacted entries (<redacted> appears when Terminal
    # does not have Location Services access in System Settings).
    networks = [n for n in networks if n.get("ssid") and n["ssid"] != "<redacted>"]
    # If system_profiler returned no real SSIDs, fall back to airport binary.
    has_ssids = bool(networks)
    if not has_ssids:
        airport_nets = _airport_scan_macos()
        if airport_nets:
            logger.info("system_profiler returned no SSIDs; using airport fallback (%d nets)", len(airport_nets))
            return airport_nets
    return networks


def _scan_linux() -> list[dict[str, Any]]:
    r = subprocess.run(
        ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,SECURITY",
         "dev", "wifi", "list", "--rescan", "yes"],
        capture_output=True, text=True, timeout=15,
    )
    networks = []
    for line in r.stdout.strip().splitlines():
        parts = line.split(":")
        if len(parts) >= 5:
            sig = int(parts[2]) if parts[2].isdigit() else 0
            networks.append({
                "ssid": parts[0] or "(hidden)",
                "bssid": parts[1],
                "signal": sig - 100 if sig > 0 else sig,
                "security": parts[4] or "Open",
                "hidden": not bool(parts[0]),
            })
    return networks


def _scan_windows() -> list[dict[str, Any]]:
    r = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, timeout=15,
    )
    networks = []
    current: dict[str, Any] = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            if current.get("ssid"):
                networks.append(current)
            current = {"ssid": line.split(":", 1)[1].strip(), "hidden": False}
        elif "BSSID" in line:
            current["bssid"] = line.split(":", 1)[1].strip()
        elif "Signal" in line:
            m = re.search(r"(\d+)", line)
            current["signal"] = int(m.group(1)) - 100 if m else 0
        elif "Authentication" in line or "Cipher" in line:
            current["security"] = line.split(":", 1)[1].strip()
    if current.get("ssid"):
        networks.append(current)
    return networks


def _parse_signal(val: str) -> int:
    m = re.search(r"-?\d+", str(val))
    return int(m.group()) if m else 0


def _parse_channel(val: str) -> int:
    m = re.search(r"\d+", str(val))
    return int(m.group()) if m else 0


# ---------------------------------------------------------------------------
# Network discovery (lightweight — no nmap required)
# ---------------------------------------------------------------------------

def _get_local_ip() -> str:
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_subnet() -> str:
    """Derive /24 subnet from local IP."""
    ip = _get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


async def _ping_host(ip: str, timeout: float = 1.0) -> dict | None:
    """Ping a single host, return info dict if alive."""
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", flag, "1", "-W" if platform.system().lower() != "windows" else "-w",
            str(int(timeout * 1000)), ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
        if proc.returncode == 0:
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                pass
            return {"ip": ip, "hostname": hostname, "alive": True}
    except (asyncio.TimeoutError, OSError):
        pass
    return None


async def discover_hosts(subnet: str | None = None) -> list[dict]:
    """Discover live hosts on the local subnet via ping sweep."""
    subnet = subnet or _get_subnet()
    # Generate IPs in /24
    base_parts = subnet.replace("/24", "").split(".")
    base = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
    ips = [f"{base}.{i}" for i in range(1, 255)]

    sem = asyncio.Semaphore(50)  # Max 50 concurrent pings

    async def bounded_ping(ip: str):
        async with sem:
            return await _ping_host(ip, timeout=1.5)

    results = await asyncio.gather(*[bounded_ping(ip) for ip in ips])
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# System metrics
# ---------------------------------------------------------------------------

def collect_system_metrics() -> dict[str, Any]:
    """Collect basic system metrics (stdlib only)."""
    metrics: dict[str, Any] = {}

    # CPU load
    try:
        load = os.getloadavg()
        metrics["cpu_load_1m"] = round(load[0], 2)
        metrics["cpu_load_5m"] = round(load[1], 2)
        metrics["cpu_load_15m"] = round(load[2], 2)
    except (OSError, AttributeError):
        pass

    # Disk usage
    try:
        usage = shutil.disk_usage("/")
        metrics["disk_total_gb"] = round(usage.total / (1024**3), 1)
        metrics["disk_used_gb"] = round(usage.used / (1024**3), 1)
        metrics["disk_free_gb"] = round(usage.free / (1024**3), 1)
        metrics["disk_pct"] = round(usage.used / usage.total * 100, 1)
    except OSError:
        pass

    # Memory (platform-specific)
    if platform.system().lower() == "darwin":
        try:
            r = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=5)
            page_size = 16384  # default on Apple Silicon
            free = wired = active = inactive = 0
            for line in r.stdout.splitlines():
                if "page size" in line.lower():
                    m = re.search(r"\d+", line)
                    if m:
                        page_size = int(m.group())
                elif "Pages free" in line:
                    m = re.search(r"\d+", line)
                    if m:
                        free = int(m.group()) * page_size
                elif "Pages active" in line:
                    m = re.search(r"\d+", line)
                    if m:
                        active = int(m.group()) * page_size
                elif "Pages inactive" in line:
                    m = re.search(r"\d+", line)
                    if m:
                        inactive = int(m.group()) * page_size
                elif "Pages wired" in line:
                    m = re.search(r"\d+", line)
                    if m:
                        wired = int(m.group()) * page_size
            used = active + wired
            total = used + free + inactive
            if total > 0:
                metrics["mem_total_gb"] = round(total / (1024**3), 1)
                metrics["mem_used_gb"] = round(used / (1024**3), 1)
                metrics["mem_pct"] = round(used / total * 100, 1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    elif platform.system().lower() == "linux":
        try:
            with open("/proc/meminfo") as f:
                info = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = int(re.search(r"\d+", parts[1]).group()) * 1024
                        info[key] = val
                total = info.get("MemTotal", 0)
                avail = info.get("MemAvailable", 0)
                if total > 0:
                    metrics["mem_total_gb"] = round(total / (1024**3), 1)
                    metrics["mem_used_gb"] = round((total - avail) / (1024**3), 1)
                    metrics["mem_pct"] = round((total - avail) / total * 100, 1)
        except (FileNotFoundError, ValueError):
            pass

    # Uptime
    try:
        if platform.system().lower() == "darwin":
            r = subprocess.run(["sysctl", "-n", "kern.boottime"],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"sec = (\d+)", r.stdout)
            if m:
                boot = int(m.group(1))
                metrics["uptime_hours"] = round((time.time() - boot) / 3600, 1)
        elif platform.system().lower() == "linux":
            with open("/proc/uptime") as f:
                metrics["uptime_hours"] = round(float(f.read().split()[0]) / 3600, 1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return metrics


# ---------------------------------------------------------------------------
# Port scan (fast TCP connect scan on common ports)
# ---------------------------------------------------------------------------

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]


async def _check_port(ip: str, port: int, timeout: float = 1.0) -> int | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, OSError):
        return None


async def scan_ports(ip: str, ports: list[int] | None = None) -> list[int]:
    """Quick TCP connect scan on common ports."""
    ports = ports or COMMON_PORTS
    results = await asyncio.gather(*[_check_port(ip, p) for p in ports])
    return [p for p in results if p is not None]


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

@dataclass
class AgentReport:
    agent_id: str
    timestamp: str
    identity: dict
    wifi_networks: list[dict]
    discovered_hosts: list[dict]
    system_metrics: dict
    local_ip: str = ""
    subnet: str = ""
    gateway: str = ""
    open_ports_by_host: dict = field(default_factory=dict)
    diagnostics: dict = field(default_factory=dict)  # ReAct diagnostic intelligence
    threat_alerts: list[dict] = field(default_factory=list)  # Threats discovered by local analysis
    threat_reports: list[dict] = field(default_factory=list)  # Detailed auto-generated reports

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# Global ReAct agent instance (persists across report cycles)
_react_agent: Any = None


def _get_react_agent() -> Any:
    """Lazy-init the probe's ReAct agent."""
    global _react_agent
    if _react_agent is None:
        from network_guardian.agent.react_agent import ProbeReActAgent
        _react_agent = ProbeReActAgent()
    return _react_agent


# ---------------------------------------------------------------------------
# Auto-protection: real-time threat notifications to the user
# ---------------------------------------------------------------------------

_ANSI = {
    "red":    "\033[1;31m",
    "yellow": "\033[1;33m",
    "orange": "\033[0;33m",
    "cyan":   "\033[1;36m",
    "reset":  "\033[0m",
    "bold":   "\033[1m",
}


def _send_os_notification(title: str, message: str) -> None:
    """Send a native OS notification so the user is alerted even if the terminal is minimised."""
    os_name = platform.system().lower()
    try:
        if os_name == "darwin":
            script = (
                f'display notification "{message}" with title "{title}" '
                f'sound name "Sosumi"'
            )
            subprocess.run(["osascript", "-e", script],
                           capture_output=True, timeout=5)
        elif os_name == "linux":
            subprocess.run(["notify-send", "-u", "critical", title, message],
                           capture_output=True, timeout=5)
        elif os_name == "windows":
            # PowerShell toast — works on Windows 10+
            ps = (
                "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;"
                f"$xml=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(0);"
                f"$xml.SelectSingleNode('//text').InnerText='{title}: {message}';"
                "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Network Guardian')"
                ".Show([Windows.UI.Notifications.ToastNotification]::new($xml))"
            )
            subprocess.run(["powershell", "-Command", ps],
                           capture_output=True, timeout=10)
    except Exception:
        pass  # Notifications are best-effort


def _emit_threat_banners(alerts: list[dict]) -> None:
    """Print coloured console banners and fire OS notifications for active threats."""
    if not alerts:
        return
    critical = [a for a in alerts if a.get("severity") == "critical"]
    high     = [a for a in alerts if a.get("severity") == "high"]
    medium   = [a for a in alerts if a.get("severity") == "medium"]

    # Console banners
    sep = "=" * 70
    print(f"\n{_ANSI['red']}{sep}")
    print(f"  ⚠  NETWORK GUARDIAN — THREAT DETECTION REPORT")
    print(f"{sep}{_ANSI['reset']}")

    for a in critical:
        print(f"{_ANSI['red']}[CRITICAL] {a.get('threat_type','').upper()}")
        print(f"  {a.get('description', '')}")
        for item in a.get("affected_items", [])[:5]:
            print(f"  → {item}")
        if a.get("remediation"):
            print(f"  FIX: {a['remediation']}{_ANSI['reset']}")
        print()

    for a in high:
        print(f"{_ANSI['yellow']}[HIGH]     {a.get('threat_type','').upper()}")
        print(f"  {a.get('description', '')}")
        for item in a.get("affected_items", [])[:5]:
            print(f"  → {item}")
        if a.get("remediation"):
            print(f"  FIX: {a['remediation']}{_ANSI['reset']}")
        print()

    for a in medium:
        print(f"{_ANSI['orange']}[MEDIUM]   {a.get('threat_type','').upper()}")
        print(f"  {a.get('description', '')}{_ANSI['reset']}")
        print()

    print(f"{_ANSI['red']}{sep}{_ANSI['reset']}\n")

    # OS notifications for critical/high only (avoid spamming medium)
    urgent = critical + high
    if urgent:
        top = urgent[0]
        sev  = top.get("severity", "high").upper()
        desc = top.get("description", "Threat detected on your network")
        extra = f" (+{len(urgent)-1} more)" if len(urgent) > 1 else ""
        _send_os_notification(
            f"⚠ Network Guardian [{sev}]{extra}",
            desc[:120],
        )


async def build_report(identity: AgentIdentity, do_discovery: bool = True,
                       do_port_scan: bool = False) -> AgentReport:
    """Collect all data and build a report."""
    logger.info("Collecting WiFi networks...")
    wifi = scan_wifi()
    logger.info("Found %d WiFi networks", len(wifi))

    local_ip = _get_local_ip()
    subnet = _get_subnet()

    hosts: list[dict] = []
    if do_discovery:
        logger.info("Discovering hosts on %s...", subnet)
        hosts = await discover_hosts(subnet)
        logger.info("Found %d live hosts", len(hosts))

    port_map: dict[str, list[int]] = {}
    if do_port_scan and hosts:
        logger.info("Scanning ports on discovered hosts...")
        for h in hosts[:20]:  # Limit to top 20 hosts
            open_p = await scan_ports(h["ip"])
            if open_p:
                port_map[h["ip"]] = open_p

    metrics = collect_system_metrics()

    # Gateway
    gateway = ""
    try:
        if platform.system().lower() == "darwin":
            r = subprocess.run(["route", "-n", "get", "default"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "gateway:" in line.lower():
                    gateway = line.split(":")[1].strip()
                    break
        elif platform.system().lower() == "linux":
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
            parts = r.stdout.split()
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Analyze for threats
    threat_alerts = []
    try:
        analyzer = ProbeThrottleAnalyzer()
        logger.debug("Analyzing %d WiFi networks for security issues", len(wifi))
        # Analyze WiFi security
        analyzer.analyze_wifi_networks(wifi)
        logger.debug("Analyzing %d discovered hosts for exposed services", len(hosts))
        # Analyze discovered hosts
        analyzer.analyze_discovered_hosts(hosts, local_subnet=subnet)
        threat_alerts = [a.to_dict() for a in analyzer.alerts]
        logger.info("Threat analysis complete: %d alert(s) detected", len(threat_alerts))
        if threat_alerts:
            for alert in threat_alerts:
                logger.warning("THREAT [%s]: %s", alert["threat_type"], alert["description"])
        # Emit console banners + OS notifications immediately so the user knows
        _emit_threat_banners(threat_alerts)
    except Exception as e:
        logger.warning("Threat analysis failed: %s", e)

    # Run ReAct diagnostic cycle
    diagnostics = {}
    threat_reports: list[dict] = []
    try:
        react = _get_react_agent()
        diag = react.run_cycle(agent_id=identity.agent_id)
        diagnostics = diag.to_dict()
        threat_reports = react.latest_threat_reports
        logger.info("ReAct cycle complete — threat score: %.0f/100 (%s)",
                     diag.threat_score, diag.risk_level)
    except Exception as e:
        logger.warning("ReAct cycle failed: %s", e)

    return AgentReport(
        agent_id=identity.agent_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        identity=asdict(identity),
        wifi_networks=wifi,
        discovered_hosts=hosts,
        system_metrics=metrics,
        local_ip=local_ip,
        subnet=subnet,
        gateway=gateway,
        open_ports_by_host=port_map,
        diagnostics=diagnostics,
        threat_alerts=threat_alerts,
        threat_reports=threat_reports,
    )


# ---------------------------------------------------------------------------
# Phone-home client
# ---------------------------------------------------------------------------

def _sign_payload(payload: bytes, key: str) -> str:
    """HMAC-SHA256 sign the payload."""
    return hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


def phone_home(base_url: str, agent_key: str, report: AgentReport,
               comms: CovertComms | None = None) -> bool:
    """Send report to the base station via covert channel. Returns True on success."""
    url = f"{base_url.rstrip('/')}/api/fleet/report"
    c = comms or build_comms()
    # Embed covert status so base station can display opsec state per agent
    report_dict = report.to_dict()
    report_dict["covert_status"] = c.status()
    payload = json.dumps(report_dict).encode()
    sig = _sign_payload(payload, agent_key)

    headers = {
        "Content-Type": "application/json",
        "X-Agent-ID": report.agent_id,
        "X-Agent-Signature": sig,
        "X-Requested-With": "XMLHttpRequest",
    }
    c = comms or build_comms()
    ok, body = c.post(url, headers, payload)
    if ok:
        if body.get("ok"):
            logger.info("Report accepted by base station ✓")
            return True
        logger.warning("Base station rejected report: %s", body.get("message"))
        return False
    logger.warning("Report delivery FAILED — base station unreachable (network change?)")
    return False


def register_with_base(base_url: str, agent_key: str, identity: AgentIdentity) -> bool:
    """Register this agent with the base station."""
    url = f"{base_url.rstrip('/')}/api/fleet/register"
    payload = json.dumps(asdict(identity)).encode()
    sig = _sign_payload(payload, agent_key)

    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Agent-ID": identity.agent_id,
            "X-Agent-Signature": sig,
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
            if body.get("ok"):
                logger.info("Registered with base station as %s", identity.agent_id)
                return True
            logger.warning("Registration rejected: %s", body.get("message"))
            return False
    except Exception as e:
        logger.error("Registration failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Agent main loop
# ---------------------------------------------------------------------------

async def agent_loop(base_url: str, agent_key: str, interval: int = 60,
                     discovery: bool = True, port_scan: bool = False,
                     comms: CovertComms | None = None) -> None:
    """Main agent loop — collect and report on interval."""
    data_dir = Path.home() / ".ng_agent"

    identity = AgentIdentity.collect(data_dir)
    logger.info("Agent ID: %s | Host: %s | OS: %s",
                identity.agent_id, identity.hostname, identity.platform_os)

    c = comms or build_comms()

    # Register
    register_with_base(base_url, agent_key, identity)

    while True:
        try:
            report = await build_report(identity, do_discovery=discovery,
                                        do_port_scan=port_scan)
            phone_home(base_url, agent_key, report, comms=c)
        except Exception as e:
            logger.error("Agent loop error: %s", e)

        logger.info("Next report in %ds...", interval)
        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Auto-start service installer (cross-platform)
# ---------------------------------------------------------------------------

_SERVICE_ID = "com.wolfpak.ng-probe"
_SERVICE_NAME = "NetworkGuardianProbe"


def _get_probe_cmd(base_url: str, key: str, interval: int = 60) -> list[str]:
    """Build the command line for the agent service."""
    # Prefer the installed entry point; fall back to python -m
    probe_bin = shutil.which("ng-probe")
    if probe_bin:
        return [probe_bin, "--base", base_url, "--key", key,
                "--interval", str(interval)]
    return [sys.executable, "-m", "network_guardian.agent",
            "--base", base_url, "--key", key, "--interval", str(interval)]


def _install_macos(base_url: str, key: str, interval: int) -> None:
    """Install a macOS LaunchAgent (auto-start on login)."""
    cmd = _get_probe_cmd(base_url, key, interval)
    plist_dir = Path.home() / "Library" / "LaunchAgents"
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / f"{_SERVICE_ID}.plist"

    log_dir = Path.home() / ".ng_agent" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # ProgramArguments
    prog_args = "\n".join(f"        <string>{a}</string>" for a in cmd)

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_SERVICE_ID}</string>
    <key>ProgramArguments</key>
    <array>
{prog_args}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/ng-probe.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/ng-probe.err.log</string>
    <key>ThrottleInterval</key>
    <integer>30</integer>
</dict>
</plist>
"""
    plist_path.write_text(plist_content)
    # Load the agent
    subprocess.run(["launchctl", "unload", str(plist_path)],
                   capture_output=True)
    r = subprocess.run(["launchctl", "load", "-w", str(plist_path)],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print(f"  [OK] Installed macOS LaunchAgent: {plist_path}")
        print(f"       Agent will auto-start on login and stay running.")
        print(f"       Logs: {log_dir}/")
    else:
        print(f"  [ERROR] Failed to load LaunchAgent: {r.stderr}")


def _uninstall_macos() -> None:
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{_SERVICE_ID}.plist"
    if plist_path.exists():
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
        plist_path.unlink()
        print(f"  [OK] Removed macOS LaunchAgent")
    else:
        print("  No LaunchAgent found.")


def _install_windows(base_url: str, key: str, interval: int) -> None:
    """Install a Windows scheduled task (auto-start on login)."""
    cmd = _get_probe_cmd(base_url, key, interval)
    cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)

    # Use Task Scheduler
    task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Network Guardian Field Agent (Wolfpak)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Hidden>true</Hidden>
  </Settings>
  <Actions>
    <Exec>
      <Command>{cmd[0]}</Command>
      <Arguments>{" ".join(cmd[1:])}</Arguments>
    </Exec>
  </Actions>
</Task>"""

    xml_path = Path.home() / ".ng_agent" / "task.xml"
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text(task_xml, encoding="utf-16")

    r = subprocess.run(
        ["schtasks", "/Create", "/TN", _SERVICE_NAME,
         "/XML", str(xml_path), "/F"],
        capture_output=True, text=True,
    )
    xml_path.unlink(missing_ok=True)

    if r.returncode == 0:
        print(f"  [OK] Installed Windows scheduled task: {_SERVICE_NAME}")
        print(f"       Agent will auto-start on login.")
        # Also start it now
        subprocess.run(["schtasks", "/Run", "/TN", _SERVICE_NAME],
                       capture_output=True)
    else:
        print(f"  [ERROR] Failed to create task: {r.stderr}")
        print(f"  Try running as Administrator.")


def _uninstall_windows() -> None:
    r = subprocess.run(
        ["schtasks", "/Delete", "/TN", _SERVICE_NAME, "/F"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        print(f"  [OK] Removed Windows scheduled task: {_SERVICE_NAME}")
    else:
        print(f"  No scheduled task found or access denied.")


def _install_linux(base_url: str, key: str, interval: int) -> None:
    """Install a Linux systemd user service (auto-start on login)."""
    cmd = _get_probe_cmd(base_url, key, interval)
    cmd_str = " ".join(cmd)

    service_dir = Path.home() / ".config" / "systemd" / "user"
    service_dir.mkdir(parents=True, exist_ok=True)
    service_path = service_dir / "ng-probe.service"

    service_content = f"""[Unit]
Description=Network Guardian Field Agent (Wolfpak)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={cmd_str}
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
"""
    service_path.write_text(service_content)
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    r = subprocess.run(["systemctl", "--user", "enable", "--now", "ng-probe.service"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print(f"  [OK] Installed Linux systemd user service: ng-probe.service")
        print(f"       Agent will auto-start on login and stay running.")
    else:
        print(f"  [ERROR] systemctl failed: {r.stderr}")


def _uninstall_linux() -> None:
    r = subprocess.run(["systemctl", "--user", "disable", "--now", "ng-probe.service"],
                       capture_output=True, text=True)
    service_path = Path.home() / ".config" / "systemd" / "user" / "ng-probe.service"
    service_path.unlink(missing_ok=True)
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    if r.returncode == 0:
        print(f"  [OK] Removed Linux systemd service")
    else:
        print(f"  No service found or not running.")


def install_service(base_url: str, key: str, interval: int = 60) -> None:
    """Install the agent as an auto-starting system service."""
    os_name = platform.system().lower()
    print(f"\n  Installing Network Guardian agent service ({os_name})...")
    if os_name == "darwin":
        _install_macos(base_url, key, interval)
    elif os_name == "windows":
        _install_windows(base_url, key, interval)
    elif os_name == "linux":
        _install_linux(base_url, key, interval)
    else:
        print(f"  Unsupported OS: {os_name}")


def uninstall_service() -> None:
    """Remove the auto-starting agent service."""
    os_name = platform.system().lower()
    print(f"\n  Removing Network Guardian agent service ({os_name})...")
    if os_name == "darwin":
        _uninstall_macos()
    elif os_name == "windows":
        _uninstall_windows()
    elif os_name == "linux":
        _uninstall_linux()
    else:
        print(f"  Unsupported OS: {os_name}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="ng-probe",
        description="Network Guardian Field Agent — scans networks and reports to base station",
    )
    parser.add_argument("--base", required=False,
                        help="Base station URL (e.g. http://192.168.1.100:8080)")
    parser.add_argument("--key", required=False,
                        help="Agent authentication key (from base station)")
    parser.add_argument("--interval", type=int, default=60,
                        help="Report interval in seconds (default: 60)")
    parser.add_argument("--no-discovery", action="store_true",
                        help="Skip network host discovery (faster)")
    parser.add_argument("--port-scan", action="store_true",
                        help="Enable port scanning on discovered hosts")
    parser.add_argument("--once", action="store_true",
                        help="Run once and exit (don't loop)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--username", "-u", help="Wolfpak username (or prompted interactively)")
    parser.add_argument("--password", "-p", help="Wolfpak password (or prompted interactively)")
    parser.add_argument("--deauth", action="store_true",
                        help="Remove stored Wolfpak auth token and exit")
    parser.add_argument("--install", action="store_true",
                        help="Install agent as auto-start system service")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove auto-start system service")
    parser.add_argument(
        "--proxy",
        help="Proxy URL for covert routing (e.g. socks5://127.0.0.1:9050, http://proxy:8080)",
    )
    parser.add_argument(
        "--tor", action="store_true",
        help="Route via Tor (auto-detect SOCKS5 on 9050/9150)",
    )
    parser.add_argument(
        "--stealth", action="store_true",
        help="Maximum stealth: long jitter, extra decoys, total log suppression",
    )
    parser.add_argument(
        "--no-jitter", action="store_true",
        help="Disable random timing delays (faster but more detectable)",
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Handle deauth
    if args.deauth:
        deauth_agent()
        return

    # Handle install/uninstall service
    if args.install:
        if not args.base or not args.key:
            print("ERROR: --base and --key required for --install")
            sys.exit(1)
        install_service(args.base, args.key, args.interval)
        return
    if args.uninstall:
        uninstall_service()
        return

    if not args.base or not args.key:
        parser.error("--base and --key are required")

    # Build covert communications channel
    comms = build_comms(
        proxy=args.proxy or "",
        use_tor=args.tor,
        jitter=not args.no_jitter,
        stealth=args.stealth,
    )
    cs = comms.status()
    logger.info("Covert channel: proxy=%s, jitter=%s, decoys=%d",
                cs["proxy"], cs["jitter"], cs["decoys"])

    # Wolfpak authentication gate
    auth_info = authenticate_agent(args.base, args.key,
                                    username=args.username,
                                    password=args.password)
    logger.info("Operator: %s | Role: %s", auth_info.get("operator"), auth_info.get("role"))

    if args.once:
        async def run_once():
            data_dir = Path.home() / ".ng_agent"
            identity = AgentIdentity.collect(data_dir)
            register_with_base(args.base, args.key, identity)
            report = await build_report(identity,
                                        do_discovery=not args.no_discovery,
                                        do_port_scan=args.port_scan)
            phone_home(args.base, args.key, report, comms=comms)
            print(json.dumps(report.to_dict(), indent=2))
        asyncio.run(run_once())
    else:
        asyncio.run(agent_loop(
            base_url=args.base,
            agent_key=args.key,
            interval=args.interval,
            discovery=not args.no_discovery,
            port_scan=args.port_scan,
            comms=comms,
        ))


if __name__ == "__main__":
    main()
