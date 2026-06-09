# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
"""
Probe Commander — JARVIS operational awareness of all field probes.

Read-only guard-rail: this module only reads data (fleet.json, TCP probes,
ICMP ping).  It never mutates state, starts/stops probes, or fires commands.

Public API
----------
list_registered_probes()   -> list[ProbeRecord]
scan_subnet_for_probes()   -> list[ProbeRecord]      (async)
health_check_probe(ip)     -> ProbeHealth            (async)
full_probe_report()        -> ProbeReport            (async, combines all above)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import platform
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("network_guardian.jarvis.probe_commander")

# ── Constants ───────────────────────────────────────────────────────────────
_PROBE_PORTS       = [8080, 8443, 5000, 4443]
_PORT_TIMEOUT      = 1.0   # seconds
_HTTP_TIMEOUT      = 2.0   # seconds
_PING_CONCURRENCY  = 40
_SUBNET_SCAN_LIMIT = 254   # /24 at most

_NG_SIGNALS = [
    "network guardian",
    "ng-probe",
    "wolfpak",
    "x-ng-",
    "/api/fleet",
    "fleet",
]

_NG_DATA_ROOT = Path(os.environ.get(
    "NG_DATA_ROOT",
    str(Path(os.environ.get("USERPROFILE", Path.home())) / ".network_guardian")
))
_FLEET_JSON = _NG_DATA_ROOT / "fleet.json"


# ── Data models ─────────────────────────────────────────────────────────────

@dataclass
class ProbeRecord:
    """A field agent (probe) — registered or discovered on the subnet."""
    agent_id:   str
    hostname:   str
    ip:         str
    status:     str          # "online" | "stale" | "offline" | "discovered"
    last_seen:  str          # ISO timestamp or age string
    port:       int  = 0
    is_ng_base: bool = False  # responded with NG signals on HTTP
    registered: bool = False  # found in fleet.json

    def age_label(self) -> str:
        return self.last_seen


@dataclass
class ProbeHealth:
    ip:        str
    reachable: bool
    latency_ms: float | None
    open_ports: list[int] = field(default_factory=list)
    is_ng_base: bool = False
    http_banner: str = ""
    error:      str  = ""


@dataclass
class ProbeReport:
    registered:    list[ProbeRecord] = field(default_factory=list)
    discovered:    list[ProbeRecord] = field(default_factory=list)
    health:        list[ProbeHealth] = field(default_factory=list)
    scanned_subnet: str = ""
    scan_duration_s: float = 0.0


# ── Fleet.json reader ────────────────────────────────────────────────────────

def list_registered_probes(fleet_path: Path | None = None) -> list[ProbeRecord]:
    """
    Read fleet.json and return all registered probe agents.
    Classifies each as online (<120 s), stale (<300 s), or offline.
    """
    path = fleet_path or _FLEET_JSON
    if not path.exists():
        log.debug("fleet.json not found at %s", path)
        return []

    try:
        raw: dict[str, Any] = json.loads(path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("fleet.json read error: %s", exc)
        return []

    now   = time.time()
    probes: list[ProbeRecord] = []

    for aid, data in raw.get("agents", {}).items():
        ls  = data.get("last_seen", 0)
        age = int(now - ls) if ls else None

        if age is None:
            status = "unknown"
            age_label = "never"
        elif age < 120:
            status = "online"
            age_label = f"{age}s ago"
        elif age < 300:
            status = "stale"
            age_label = f"{age}s ago"
        else:
            status = "offline"
            # human-readable for long durations
            if age < 3600:
                age_label = f"{age // 60}m ago"
            elif age < 86400:
                age_label = f"{age // 3600}h ago"
            else:
                age_label = f"{age // 86400}d ago"

        ident = data.get("identity", {})
        ip    = (
            data.get("last_report", {}).get("local_ip", "")
            or ident.get("ip", "")
        )

        probes.append(ProbeRecord(
            agent_id   = aid,
            hostname   = ident.get("hostname", aid),
            ip         = ip,
            status     = status,
            last_seen  = age_label,
            registered = True,
        ))

    return probes


# ── Subnet derivation ────────────────────────────────────────────────────────

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _derive_subnet(registered: list[ProbeRecord]) -> str:
    """Prefer a subnet that contains registered probe IPs; fall back to local."""
    for p in registered:
        if p.ip and not p.ip.startswith("127."):
            net = ipaddress.ip_interface(f"{p.ip}/24").network
            return str(net)
    local = _local_ip()
    net   = ipaddress.ip_interface(f"{local}/24").network
    return str(net)


# ── Async probe helpers ──────────────────────────────────────────────────────

async def _ping(ip: str, sem: asyncio.Semaphore) -> bool:
    async with sem:
        flag = "-n" if platform.system() == "Windows" else "-c"
        wait = "-w" if platform.system() == "Windows" else "-W"
        cmd  = ["ping", flag, "1", wait, "500", ip]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            return proc.returncode == 0
        except Exception:
            return False


async def _tcp_open(ip: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=_PORT_TIMEOUT
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _http_banner(ip: str, port: int) -> tuple[str, bool]:
    """Return (banner, is_ng_base)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=_HTTP_TIMEOUT
        )
        req = (
            f"GET / HTTP/1.0\r\nHost: {ip}:{port}\r\n"
            f"X-Requested-With: XMLHttpRequest\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        try:
            raw = await asyncio.wait_for(reader.read(2048), timeout=_HTTP_TIMEOUT)
        except asyncio.TimeoutError:
            raw = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        text   = raw.decode("utf-8", errors="replace")
        banner = text[:200].replace("\r\n", " | ").replace("\n", " | ")
        is_ng  = any(sig in text.lower() for sig in _NG_SIGNALS)
        return banner, is_ng
    except Exception:
        return "", False


# ── Health check ─────────────────────────────────────────────────────────────

async def health_check_probe(ip: str) -> ProbeHealth:
    """
    Ping an IP and check which probe ports are open.
    Returns a ProbeHealth record.  Never raises.
    """
    result = ProbeHealth(ip=ip, reachable=False, latency_ms=None)
    try:
        t0       = time.perf_counter()
        sem      = asyncio.Semaphore(1)
        alive    = await _ping(ip, sem)
        latency  = (time.perf_counter() - t0) * 1000

        result.reachable  = alive
        result.latency_ms = round(latency, 1) if alive else None

        # Check probe ports concurrently
        port_results = await asyncio.gather(
            *[_tcp_open(ip, p) for p in _PROBE_PORTS],
            return_exceptions=True,
        )
        result.open_ports = [
            p for p, ok in zip(_PROBE_PORTS, port_results)
            if ok is True
        ]

        # If any port is open, grab HTTP banner
        if result.open_ports:
            banner, is_ng = await _http_banner(ip, result.open_ports[0])
            result.http_banner = banner
            result.is_ng_base  = is_ng

    except Exception as exc:
        result.error = str(exc)

    return result


# ── Subnet scan ──────────────────────────────────────────────────────────────

async def scan_subnet_for_probes(
    subnet: str | None = None,
    registered: list[ProbeRecord] | None = None,
) -> list[ProbeRecord]:
    """
    Ping-sweep the /24 subnet and check each live host for NG probe ports.
    Returns ProbeRecord list for any hosts that look like NG probes/base-stations.
    Does NOT include already-registered probes (those have their own entries).
    """
    reg = registered or list_registered_probes()
    subnet = subnet or _derive_subnet(reg)
    known_ips: set[str] = {p.ip for p in reg if p.ip}

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        log.warning("Invalid subnet: %s", subnet)
        return []

    hosts = list(network.hosts())[:_SUBNET_SCAN_LIMIT]
    sem   = asyncio.Semaphore(_PING_CONCURRENCY)

    # Ping sweep
    ping_tasks   = [_ping(str(h), sem) for h in hosts]
    ping_results = await asyncio.gather(*ping_tasks, return_exceptions=True)

    live_hosts = [
        str(h) for h, ok in zip(hosts, ping_results)
        if ok is True and str(h) not in known_ips
    ]

    # Port check on live unknown hosts
    discovered: list[ProbeRecord] = []
    for ip in live_hosts:
        port_results = await asyncio.gather(
            *[_tcp_open(ip, p) for p in _PROBE_PORTS],
            return_exceptions=True,
        )
        open_ports = [p for p, ok in zip(_PROBE_PORTS, port_results) if ok is True]
        if not open_ports:
            continue

        banner, is_ng = await _http_banner(ip, open_ports[0])

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ip

        if is_ng or open_ports:
            discovered.append(ProbeRecord(
                agent_id   = f"discovered-{ip}",
                hostname   = hostname,
                ip         = ip,
                status     = "discovered",
                last_seen  = "just now",
                port       = open_ports[0] if open_ports else 0,
                is_ng_base = is_ng,
                registered = False,
            ))

    return discovered


# ── Full report ──────────────────────────────────────────────────────────────

async def full_probe_report(subnet_override: str | None = None) -> ProbeReport:
    """
    Compose a full probe report:
      1. List registered probes from fleet.json
      2. Health-check each registered probe that has a known IP
      3. Scan subnet for unregistered probe candidates
    """
    t0 = time.perf_counter()
    report = ProbeReport()

    # 1. Registered
    report.registered = list_registered_probes()

    # 2. Health-check registered probes
    health_tasks = [
        health_check_probe(p.ip)
        for p in report.registered
        if p.ip
    ]
    if health_tasks:
        report.health = list(await asyncio.gather(*health_tasks, return_exceptions=False))

    # 3. Subnet scan for unregistered
    subnet = subnet_override or _derive_subnet(report.registered)
    report.scanned_subnet = subnet
    report.discovered = await scan_subnet_for_probes(subnet, report.registered)

    report.scan_duration_s = round(time.perf_counter() - t0, 2)
    return report


# ── Sync wrapper (for JARVIS command handlers that aren't async) ──────────────

def run_full_probe_report(subnet_override: str | None = None) -> ProbeReport:
    """Blocking wrapper for full_probe_report() — safe to call from any thread."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already inside an event loop (e.g. notebook) — use run_coroutine_threadsafe
            import concurrent.futures
            fut = asyncio.run_coroutine_threadsafe(
                full_probe_report(subnet_override), loop
            )
            return fut.result(timeout=30)
        else:
            return loop.run_until_complete(full_probe_report(subnet_override))
    except RuntimeError:
        # No loop — create a fresh one
        return asyncio.run(full_probe_report(subnet_override))
