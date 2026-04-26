#!/usr/bin/env python3
"""
Network Guardian — Standalone Field Agent
==========================================
Wolf-Pak Innovations LLC  |  Copyright © 2026

Pre-configured for: https://network-guardian-cc8900c70290.herokuapp.com

REQUIREMENTS: Python 3.11+  (nothing else to install)

QUICK START:
  python3 ng_probe_standalone.py

FIRST RUN: You will be prompted for your Wolfpak username and password.
           Ask your administrator to create your account on the dashboard.

INSTALL AS BACKGROUND SERVICE (runs forever, auto-starts on reboot):
  python3 ng_probe_standalone.py --install

DASHBOARD (live fleet feed):
  https://network-guardian-cc8900c70290.herokuapp.com
  Login: your Wolfpak username + password
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# BASE STATION CONFIG — pre-configured, do not change
# ---------------------------------------------------------------------------
_BASE_URL  = "https://network-guardian-cc8900c70290.herokuapp.com"
_FLEET_KEY = "eNygMdjbr5om9cSL1T5on4s4A1srY7Dg2ro-SpKdzYc"
_INTERVAL  = 60   # seconds between reports

# ---------------------------------------------------------------------------
# stdlib imports only — zero pip deps
# ---------------------------------------------------------------------------
import argparse
import asyncio
import getpass
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
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("ng-probe")

_AGENT_DIR     = Path.home() / ".ng_agent"
_AUTH_FILE     = "wolfpak_auth.json"
_TOKEN_LIFETIME = 30 * 86400   # 30 days

_ANSI = {
    "red":    "\033[1;31m", "yellow": "\033[1;33m", "orange": "\033[0;33m",
    "cyan":   "\033[1;36m", "green":  "\033[1;32m",
    "reset":  "\033[0m",    "bold":   "\033[1m",
}

BANNER = f"""
{_ANSI['cyan']}╔══════════════════════════════════════════════════╗
║   🛡  NETWORK GUARDIAN — Field Agent (Wolfpak)  ║
║   Base: {_BASE_URL[:46]} ║
╚══════════════════════════════════════════════════╝{_ANSI['reset']}
"""


# ===========================================================================
# Authentication
# ===========================================================================

def _auth_path() -> Path:
    return _AGENT_DIR / _AUTH_FILE


def _load_auth_token() -> dict | None:
    p = _auth_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        if time.time() - data.get("authenticated_at", 0) > _TOKEN_LIFETIME:
            p.unlink(missing_ok=True)
            return None
        return data
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def _save_auth_token(data: dict) -> None:
    p = _auth_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def authenticate(username: str | None = None, password: str | None = None) -> dict:
    cached = _load_auth_token()
    if cached:
        days_left = max(0, int((_TOKEN_LIFETIME - (time.time() - cached["authenticated_at"])) / 86400))
        logger.info("Authenticated as %s (token valid %dd)", cached.get("operator", "?"), days_left)
        return cached

    print(f"\n{_ANSI['bold']}══ WOLFPAK AUTHENTICATION ══{_ANSI['reset']}")
    print("  Authorised Wolfpak members only.")
    print(f"  Contact your administrator for credentials.\n")
    try:
        if not username:
            username = input("  Username: ").strip()
        if not password:
            password = getpass.getpass("  Password: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Cancelled.")
        sys.exit(0)

    if not username or not password:
        print("  ERROR: credentials required.")
        sys.exit(1)

    payload = json.dumps({"username": username, "password": password}).encode()
    sig = hmac.new(_FLEET_KEY.encode(), payload, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        f"{_BASE_URL}/api/fleet/auth", data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-Agent-Signature": sig,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"\n  {_ANSI['red']}ACCESS DENIED — Invalid credentials or unauthorized.{_ANSI['reset']}")
        else:
            print(f"\n  {_ANSI['red']}Auth failed: HTTP {e.code}{_ANSI['reset']}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {_ANSI['red']}Cannot reach base station: {e}{_ANSI['reset']}")
        sys.exit(1)

    if not body.get("ok"):
        print(f"\n  {_ANSI['red']}ACCESS DENIED — {body.get('message', 'Unknown')}{_ANSI['reset']}")
        sys.exit(1)

    token = {
        "operator":         body.get("operator", username),
        "agent_token":      body.get("agent_token", ""),
        "role":             body.get("role", "operator"),
        "authenticated_at": int(time.time()),
    }
    _save_auth_token(token)
    print(f"\n  {_ANSI['green']}✓ ACCESS GRANTED — Welcome, {token['operator']}.{_ANSI['reset']}")
    print(f"  Token cached for {_TOKEN_LIFETIME // 86400} days.\n")
    return token


# ===========================================================================
# Agent Identity
# ===========================================================================

def _get_or_create_id() -> str:
    path = _AGENT_DIR / ".ng_agent_id"
    if path.exists():
        return path.read_text().strip()
    agent_id = f"NG-{secrets.token_hex(4).upper()}"
    _AGENT_DIR.mkdir(parents=True, exist_ok=True)
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
    def collect(cls) -> AgentIdentity:
        import uuid
        mac = ":".join(f"{b:02x}" for b in uuid.getnode().to_bytes(6, "big"))
        return cls(
            agent_id=_get_or_create_id(),
            hostname=socket.gethostname(),
            platform_os=f"{platform.system()} {platform.release()}",
            arch=platform.machine(),
            python_ver=platform.python_version(),
            mac_addr=mac,
        )


# ===========================================================================
# WiFi scanning (macOS / Linux / Windows)
# ===========================================================================

def _normalise_security(raw: str) -> str:
    if not raw or raw in ("None", "none"):
        return "Open"
    r = raw.lower()
    if "wpa3" in r: return "WPA3"
    if "wpa2" in r or "rsn" in r: return "WPA2"
    if "wpa" in r: return "WPA"
    if "wep" in r: return "WEP"
    if "open" in r: return "Open"
    if raw in ("WPA3", "WPA2", "WPA", "WEP", "Open", "Unknown"): return raw
    return raw.replace("spairport_security_mode_", "").replace("_", " ").upper() or "Unknown"


def _parse_int(s: str) -> int:
    m = re.search(r"-?\d+", str(s))
    return int(m.group()) if m else 0


def _scan_macos() -> list[dict]:
    try:
        r = subprocess.run(["system_profiler", "SPAirPortDataType", "-json"],
                           capture_output=True, text=True, timeout=20)
        data = json.loads(r.stdout)
        nets = []
        interfaces = (data.get("SPAirPortDataType", [{}])[0]
                         .get("spairport_airport_interfaces", []))
        for iface in interfaces:
            other = iface.get("spairport_airport_other_local_wireless_networks", [])
            current = iface.get("spairport_current_network_information", {})
            conn_ssid = current.get("_name", "") if current else ""
            for net in ([current] if current else []) + other:
                ssid = net.get("_name", "")
                if not ssid or "<redacted>" in ssid.lower() or ssid.startswith("0x"):
                    continue
                rssi_raw = net.get("spairport_network_signal_noise", "")
                rssi = _parse_int(rssi_raw.split("/")[0].strip() if rssi_raw else "0")
                ch = _parse_int(net.get("spairport_network_channel", "0"))
                nets.append({
                    "ssid": ssid, "bssid": net.get("spairport_network_bssid", ""),
                    "signal": rssi, "channel": ch,
                    "frequency": "5 GHz" if ch > 14 else "2.4 GHz",
                    "security": _normalise_security(net.get("spairport_security_mode", "Unknown")),
                    "hidden": False, "connected": ssid == conn_ssid,
                })
        return nets
    except Exception:
        pass
    # Fallback: airport binary
    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework"
               "/Versions/Current/Resources/airport")
    if Path(airport).exists():
        try:
            r = subprocess.run([airport, "-s"], capture_output=True, text=True, timeout=15)
            nets = []
            for line in r.stdout.splitlines()[1:]:
                m = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', line, re.I)
                if not m:
                    continue
                ssid = line[:m.start()].strip()
                tail = line[m.start():].split()
                bssid = tail[0] if tail else ""
                rssi  = _parse_int(tail[1]) if len(tail) > 1 else 0
                ch    = _parse_int(tail[2].split(",")[0]) if len(tail) > 2 else 0
                sec   = " ".join(tail[5:]) if len(tail) > 5 else "Unknown"
                if ssid:
                    nets.append({"ssid": ssid, "bssid": bssid, "signal": rssi,
                                  "channel": ch, "frequency": "5 GHz" if ch > 14 else "2.4 GHz",
                                  "security": _normalise_security(sec),
                                  "hidden": False, "connected": False})
            return nets
        except Exception:
            pass
    return []


def _scan_linux() -> list[dict]:
    try:
        r = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi"],
                           capture_output=True, text=True, timeout=15)
        nets = []
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 5:
                ssid, bssid, signal, chan, sec = parts[0], parts[1], parts[2], parts[3], ":".join(parts[4:])
                if ssid:
                    nets.append({"ssid": ssid, "bssid": bssid,
                                  "signal": _parse_int(signal) - 100,
                                  "channel": _parse_int(chan),
                                  "frequency": "5 GHz" if _parse_int(chan) > 14 else "2.4 GHz",
                                  "security": _normalise_security(sec.strip()),
                                  "hidden": False, "connected": False})
        return nets
    except Exception:
        return []


def _scan_windows() -> list[dict]:
    try:
        r = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                           capture_output=True, text=True, timeout=15)
        nets, cur = [], {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                if cur.get("ssid"): nets.append(cur)
                cur = {"ssid": line.split(":", 1)[1].strip(), "hidden": False}
            elif "BSSID" in line: cur["bssid"] = line.split(":", 1)[1].strip()
            elif "Signal" in line:
                m = re.search(r"(\d+)", line)
                cur["signal"] = int(m.group(1)) - 100 if m else 0
            elif "Authentication" in line:
                cur["security"] = _normalise_security(line.split(":", 1)[1].strip())
        if cur.get("ssid"): nets.append(cur)
        return nets
    except Exception:
        return []


def scan_wifi() -> list[dict]:
    os_name = platform.system().lower()
    try:
        if os_name == "darwin":   return _scan_macos()
        if os_name == "linux":    return _scan_linux()
        if os_name == "windows":  return _scan_windows()
    except Exception as e:
        logger.warning("WiFi scan failed: %s", e)
    return []


# ===========================================================================
# Network discovery
# ===========================================================================

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _subnet() -> str:
    parts = _local_ip().split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


async def _ping(ip: str) -> dict | None:
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", flag, "1", "-W" if platform.system().lower() != "windows" else "-w",
            "1500", ip,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=2.5)
        if proc.returncode == 0:
            hostname = ""
            try: hostname = socket.gethostbyaddr(ip)[0]
            except Exception: pass
            return {"ip": ip, "hostname": hostname, "alive": True}
    except Exception:
        pass
    return None


async def discover_hosts(subnet: str) -> list[dict]:
    base = ".".join(subnet.replace("/24", "").split(".")[:3])
    sem = asyncio.Semaphore(40)
    async def bounded(ip): 
        async with sem: return await _ping(ip)
    results = await asyncio.gather(*[bounded(f"{base}.{i}") for i in range(1, 255)])
    return [r for r in results if r]


# ===========================================================================
# System metrics
# ===========================================================================

def system_metrics() -> dict:
    m: dict[str, Any] = {}
    try:
        load = os.getloadavg()
        m["cpu_load_1m"] = round(load[0], 2)
    except (OSError, AttributeError):
        pass
    try:
        u = shutil.disk_usage("/")
        m["disk_pct"] = round(u.used / u.total * 100, 1)
        m["disk_free_gb"] = round(u.free / (1024**3), 1)
    except OSError:
        pass
    os_name = platform.system().lower()
    if os_name == "darwin":
        try:
            r = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=5)
            ps, free, active, wired = 16384, 0, 0, 0
            for line in r.stdout.splitlines():
                if "page size" in line.lower():
                    match = re.search(r"\d+", line)
                    if match: ps = int(match.group())
                elif "Pages free" in line:
                    match = re.search(r"\d+", line)
                    if match: free = int(match.group()) * ps
                elif "Pages active" in line:
                    match = re.search(r"\d+", line)
                    if match: active = int(match.group()) * ps
                elif "Pages wired" in line:
                    match = re.search(r"\d+", line)
                    if match: wired = int(match.group()) * ps
            used = active + wired
            total = used + free
            if total > 0:
                m["mem_used_gb"] = round(used / (1024**3), 1)
                m["mem_pct"] = round(used / total * 100, 1)
        except Exception: pass
    elif os_name == "linux":
        try:
            with open("/proc/meminfo") as f:
                info = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        info[parts[0].strip()] = int(re.search(r"\d+", parts[1]).group()) * 1024
            total = info.get("MemTotal", 0)
            avail = info.get("MemAvailable", 0)
            if total:
                m["mem_pct"] = round((total - avail) / total * 100, 1)
        except Exception: pass
    try:
        if os_name == "darwin":
            r = subprocess.run(["sysctl", "-n", "kern.boottime"],
                               capture_output=True, text=True, timeout=5)
            match = re.search(r"sec = (\d+)", r.stdout)
            if match:
                m["uptime_hours"] = round((time.time() - int(match.group(1))) / 3600, 1)
        elif os_name == "linux":
            with open("/proc/uptime") as f:
                m["uptime_hours"] = round(float(f.read().split()[0]) / 3600, 1)
    except Exception: pass
    # Process / connection counts via netstat
    try:
        if os_name in ("darwin", "linux"):
            r = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=5)
            lines = r.stdout.splitlines()
            m["connections"] = sum(1 for l in lines if "ESTABLISHED" in l)
            m["listening_ports"] = sum(1 for l in lines if "LISTEN" in l)
            m["external_conns"] = sum(
                1 for l in lines
                if "ESTABLISHED" in l
                and not any(pfx in l for pfx in ["127.", "0.0.0.0", "::1", "::"])
            )
    except Exception: pass
    try:
        if os_name in ("darwin", "linux"):
            r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
            m["processes"] = max(0, len(r.stdout.splitlines()) - 1)
    except Exception: pass
    return m


# ===========================================================================
# Gateway detection
# ===========================================================================

def _gateway() -> str:
    try:
        os_name = platform.system().lower()
        if os_name == "darwin":
            r = subprocess.run(["route", "-n", "get", "default"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "gateway:" in line.lower():
                    return line.split(":")[1].strip()
        elif os_name == "linux":
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
            parts = r.stdout.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
        elif os_name == "windows":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw: return gw
    except Exception:
        pass
    return ""


# ===========================================================================
# OS notification
# ===========================================================================

def _notify(title: str, msg: str) -> None:
    os_name = platform.system().lower()
    try:
        if os_name == "darwin":
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{msg}" with title "{title}" sound name "Sosumi"'],
                capture_output=True, timeout=5)
        elif os_name == "linux":
            subprocess.run(["notify-send", "-u", "critical", title, msg],
                           capture_output=True, timeout=5)
    except Exception:
        pass


def _print_threats(alerts: list[dict]) -> None:
    if not alerts: return
    sep = "=" * 68
    print(f"\n{_ANSI['red']}{sep}")
    print(f"  ⚠  NETWORK GUARDIAN — THREAT DETECTION")
    print(f"{sep}{_ANSI['reset']}")
    for a in alerts:
        sev = a.get("severity", "medium").upper()
        col = _ANSI["red"] if sev == "CRITICAL" else _ANSI["yellow"] if sev == "HIGH" else _ANSI["orange"]
        print(f"{col}[{sev}] {a.get('threat_type','').upper()}")
        print(f"  {a.get('description', '')}{_ANSI['reset']}")
        for item in a.get("affected_items", [])[:3]:
            print(f"  → {item}")
        print()
    print(f"{_ANSI['red']}{sep}{_ANSI['reset']}\n")
    urgent = [a for a in alerts if a.get("severity") in ("critical", "high")]
    if urgent:
        top = urgent[0]
        _notify(f"⚠ Network Guardian [{top.get('severity','').upper()}]",
                top.get("description", "Threat detected")[:120])


# ===========================================================================
# Basic threat analysis (no external deps)
# ===========================================================================

_SUSPICIOUS_PORTS = {21, 23, 25, 110, 135, 139, 445, 1433, 3389, 5900}
_OPEN_SECURITY_SSIDS = re.compile(r'(free|guest|open|public|hotel|airport)', re.I)

def analyze_threats(wifi: list[dict], hosts: list[dict], metrics: dict) -> list[dict]:
    alerts = []

    # Open WiFi networks
    open_nets = [n for n in wifi if n.get("security", "Open") == "Open" and n.get("ssid")]
    if open_nets:
        alerts.append({
            "threat_type": "open_wifi",
            "severity": "medium",
            "description": f"{len(open_nets)} open (unencrypted) WiFi network(s) detected",
            "affected_items": [n["ssid"] for n in open_nets[:5]],
            "remediation": "Do not connect to open WiFi networks.",
        })

    # Weak WEP networks
    wep_nets = [n for n in wifi if "WEP" in n.get("security", "")]
    if wep_nets:
        alerts.append({
            "threat_type": "weak_encryption",
            "severity": "high",
            "description": f"{len(wep_nets)} network(s) using broken WEP encryption",
            "affected_items": [n["ssid"] for n in wep_nets[:5]],
            "remediation": "WEP is completely broken. Upgrade to WPA3.",
        })

    # High CPU load
    if metrics.get("cpu_load_1m", 0) > 5.0:
        alerts.append({
            "threat_type": "high_cpu",
            "severity": "medium",
            "description": f"Unusually high CPU load: {metrics['cpu_load_1m']}",
            "affected_items": [],
            "remediation": "Investigate running processes for suspicious activity.",
        })

    # Many external connections
    ext = metrics.get("external_conns", 0)
    if ext > 20:
        alerts.append({
            "threat_type": "excessive_connections",
            "severity": "high" if ext > 50 else "medium",
            "description": f"{ext} external network connections detected",
            "affected_items": [],
            "remediation": "Review active connections for data exfiltration.",
        })

    return alerts


# ===========================================================================
# Report building
# ===========================================================================

@dataclass
class Report:
    agent_id: str
    timestamp: str
    identity: dict
    wifi_networks: list
    discovered_hosts: list
    system_metrics: dict
    local_ip: str = ""
    subnet: str = ""
    gateway: str = ""
    threat_alerts: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


async def build_report(identity: AgentIdentity, do_discovery: bool = True) -> Report:
    logger.info("Scanning WiFi...")
    wifi = scan_wifi()
    logger.info("Found %d WiFi networks", len(wifi))

    local_ip = _local_ip()
    subnet = _subnet()
    gw = _gateway()

    hosts: list[dict] = []
    if do_discovery:
        logger.info("Discovering hosts on %s...", subnet)
        hosts = await discover_hosts(subnet)
        logger.info("Found %d live hosts", len(hosts))

    metrics = system_metrics()
    threats = analyze_threats(wifi, hosts, metrics)
    if threats:
        _print_threats(threats)

    return Report(
        agent_id=identity.agent_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        identity=asdict(identity),
        wifi_networks=wifi,
        discovered_hosts=hosts,
        system_metrics=metrics,
        local_ip=local_ip,
        subnet=subnet,
        gateway=gw,
        threat_alerts=threats,
    )


# ===========================================================================
# Phone home
# ===========================================================================

def _sign(payload: bytes) -> str:
    return hmac.new(_FLEET_KEY.encode(), payload, hashlib.sha256).hexdigest()


def register(identity: AgentIdentity) -> bool:
    payload = json.dumps(asdict(identity)).encode()
    req = urllib.request.Request(
        f"{_BASE_URL}/api/fleet/register", data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Agent-ID": identity.agent_id,
            "X-Agent-Signature": _sign(payload),
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.loads(r.read())
            if body.get("ok"):
                logger.info("Registered as %s", identity.agent_id)
                return True
    except Exception as e:
        logger.warning("Registration error: %s", e)
    return False


def phone_home(report: Report) -> bool:
    payload = json.dumps(report.to_dict()).encode()
    req = urllib.request.Request(
        f"{_BASE_URL}/api/fleet/report", data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Agent-ID": report.agent_id,
            "X-Agent-Signature": _sign(payload),
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.loads(r.read())
            if body.get("ok"):
                logger.info("✓ Report accepted [%s]", report.agent_id)
                return True
    except Exception as e:
        logger.warning("Phone-home failed: %s", e)
    return False


# ===========================================================================
# Service installer (macOS / Linux / Windows)
# ===========================================================================

_SERVICE_ID   = "com.wolfpak.ng-probe"
_SERVICE_NAME = "NetworkGuardianProbe"


def _self_cmd() -> list[str]:
    return [sys.executable, str(Path(__file__).resolve()),
            "--username", "_cached_", "--interval", str(_INTERVAL)]


def install_service() -> None:
    os_name = platform.system().lower()
    cmd = _self_cmd()

    if os_name == "darwin":
        plist_dir = Path.home() / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        log_dir = _AGENT_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        prog = "\n".join(f"        <string>{a}</string>" for a in cmd)
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>{_SERVICE_ID}</string>
    <key>ProgramArguments</key><array>{prog}</array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{log_dir}/ng-probe.out.log</string>
    <key>StandardErrorPath</key><string>{log_dir}/ng-probe.err.log</string>
    <key>ThrottleInterval</key><integer>30</integer>
</dict></plist>"""
        p = plist_dir / f"{_SERVICE_ID}.plist"
        p.write_text(plist)
        subprocess.run(["launchctl", "unload", str(p)], capture_output=True)
        r = subprocess.run(["launchctl", "load", "-w", str(p)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  {_ANSI['green']}[OK] macOS LaunchAgent installed — auto-starts on login{_ANSI['reset']}")
            print(f"       Logs: {log_dir}/")
        else:
            print(f"  {_ANSI['red']}[ERROR] {r.stderr}{_ANSI['reset']}")

    elif os_name == "linux":
        svc_dir = Path.home() / ".config" / "systemd" / "user"
        svc_dir.mkdir(parents=True, exist_ok=True)
        (svc_dir / "ng-probe.service").write_text(
            f"[Unit]\nDescription=Network Guardian Field Agent\nAfter=network.target\n\n"
            f"[Service]\nType=simple\nExecStart={' '.join(cmd)}\nRestart=always\nRestartSec=30\n\n"
            f"[Install]\nWantedBy=default.target\n"
        )
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        r = subprocess.run(["systemctl", "--user", "enable", "--now", "ng-probe.service"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  {_ANSI['green']}[OK] Linux systemd service installed{_ANSI['reset']}")
        else:
            print(f"  {_ANSI['red']}[ERROR] {r.stderr}{_ANSI['reset']}")

    elif os_name == "windows":
        cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)
        r = subprocess.run(
            ["schtasks", "/Create", "/TN", _SERVICE_NAME, "/SC", "ONLOGON",
             "/TR", cmd_str, "/RL", "HIGHEST", "/F"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            print(f"  {_ANSI['green']}[OK] Windows scheduled task installed — auto-starts on login{_ANSI['reset']}")
            subprocess.run(["schtasks", "/Run", "/TN", _SERVICE_NAME], capture_output=True)
        else:
            print(f"  {_ANSI['red']}[ERROR] {r.stderr} (try running as Administrator){_ANSI['reset']}")


def uninstall_service() -> None:
    os_name = platform.system().lower()
    if os_name == "darwin":
        p = Path.home() / "Library" / "LaunchAgents" / f"{_SERVICE_ID}.plist"
        if p.exists():
            subprocess.run(["launchctl", "unload", str(p)], capture_output=True)
            p.unlink()
            print(f"  {_ANSI['green']}[OK] LaunchAgent removed{_ANSI['reset']}")
        else:
            print("  No LaunchAgent found.")
    elif os_name == "linux":
        subprocess.run(["systemctl", "--user", "disable", "--now", "ng-probe.service"],
                       capture_output=True)
        svc = Path.home() / ".config" / "systemd" / "user" / "ng-probe.service"
        svc.unlink(missing_ok=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        print(f"  {_ANSI['green']}[OK] systemd service removed{_ANSI['reset']}")
    elif os_name == "windows":
        r = subprocess.run(["schtasks", "/Delete", "/TN", _SERVICE_NAME, "/F"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  {_ANSI['green']}[OK] Scheduled task removed{_ANSI['reset']}")
        else:
            print("  Task not found or access denied.")


# ===========================================================================
# Main loop
# ===========================================================================

async def agent_loop(do_discovery: bool = True, interval: int = _INTERVAL) -> None:
    identity = AgentIdentity.collect()
    logger.info("Agent ID: %s | Host: %s | OS: %s",
                identity.agent_id, identity.hostname, identity.platform_os)

    register(identity)
    print(f"  {_ANSI['cyan']}📡 Phoning home every {interval}s")
    print(f"  📊 Live fleet feed: {_BASE_URL}/fleet{_ANSI['reset']}\n")

    while True:
        try:
            report = await build_report(identity, do_discovery=do_discovery)
            ok = phone_home(report)
            status = f"{_ANSI['green']}✓ sent{_ANSI['reset']}" if ok else f"{_ANSI['red']}✗ failed{_ANSI['reset']}"
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] Report {status} "
                  f"| WiFi: {len(report.wifi_networks)} | Hosts: {len(report.discovered_hosts)} "
                  f"| Threats: {len(report.threat_alerts)}")
        except Exception as e:
            logger.error("Loop error: %s", e)
        await asyncio.sleep(interval)


# ===========================================================================
# CLI
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ng-probe-standalone",
        description="Network Guardian Standalone Field Agent (Wolfpak)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
DASHBOARD (live fleet feed):
  {_BASE_URL}/fleet
  Login with your Wolfpak credentials

FIRST RUN: Will prompt for your Wolfpak username and password.

EXAMPLES:
  python3 ng_probe_standalone.py                 # run now (interactive auth)
  python3 ng_probe_standalone.py --install       # install as background service
  python3 ng_probe_standalone.py --uninstall     # remove background service
  python3 ng_probe_standalone.py --once          # single report, then exit
  python3 ng_probe_standalone.py --no-discovery  # skip host sweep (faster)
""",
    )
    parser.add_argument("--username", "-u", help="Wolfpak username")
    parser.add_argument("--password", "-p", help="Wolfpak password")
    parser.add_argument("--interval", type=int, default=_INTERVAL,
                        help=f"Seconds between reports (default: {_INTERVAL})")
    parser.add_argument("--no-discovery", action="store_true",
                        help="Skip host discovery sweep")
    parser.add_argument("--once", action="store_true",
                        help="Run one report then exit")
    parser.add_argument("--install", action="store_true",
                        help="Install as auto-start background service")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove background service")
    parser.add_argument("--deauth", action="store_true",
                        help="Clear stored auth token")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    if args.deauth:
        p = _auth_path()
        if p.exists():
            p.unlink()
            print("  Auth token cleared.")
        else:
            print("  No auth token found.")
        return

    if args.install:
        # Must auth first so the cached token is available when running as service
        authenticate(args.username, args.password)
        install_service()
        print(f"\n  {_ANSI['bold']}The agent is now running in the background.")
        print(f"  Watch it live: {_BASE_URL}/fleet{_ANSI['reset']}")
        return

    if args.uninstall:
        uninstall_service()
        return

    # Interactive / one-shot run
    auth = authenticate(args.username, args.password)
    print(f"  Operator : {_ANSI['bold']}{auth['operator']}{_ANSI['reset']}")
    print(f"  Role     : {auth['role']}")
    print(f"  Base     : {_BASE_URL}")
    print(f"  Interval : every {args.interval}s\n")

    if args.once:
        async def run_once() -> None:
            identity = AgentIdentity.collect()
            register(identity)
            report = await build_report(identity, do_discovery=not args.no_discovery)
            phone_home(report)
            print(f"\n  Done. View report at: {_BASE_URL}/fleet")
        asyncio.run(run_once())
    else:
        try:
            asyncio.run(agent_loop(
                do_discovery=not args.no_discovery,
                interval=args.interval,
            ))
        except KeyboardInterrupt:
            print(f"\n  {_ANSI['yellow']}Agent stopped.{_ANSI['reset']}")


if __name__ == "__main__":
    main()
