"""
scan_for_probes.py — Sweep the local subnet for active NG probes not yet on the fleet map.

Usage:
    python scan_for_probes.py [--subnet 192.168.1.0/24] [--base http://127.0.0.1:8080]

How it works:
  1. Loads the fleet map fresh from disk (bypasses dashboard cache).
  2. Derives the target subnet from known fleet agent IPs (or --subnet override).
  3. Concurrent ping-sweep of every host in the subnet.
  4. For each live host NOT in fleet: checks open ports, probes HTTP/8080 for NG
     base-station headers, and tries a reverse-DNS lookup.
  5. Reports a ranked list of "likely probe" candidates.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

FLEET_JSON = Path.home() / ".network_guardian" / "fleet.json"
DEFAULT_BASE = "http://127.0.0.1:8080"
PROBE_PORTS = [8080, 8443, 5000, 4443]   # ports a base-station or probe relay might use
PING_CONCURRENCY = 60
PORT_TIMEOUT = 1.2    # seconds per port check
HTTP_TIMEOUT = 3.0    # seconds for HTTP banner grab


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FleetAgent:
    agent_id: str
    hostname: str
    ip: str
    status: str       # online | stale | offline
    last_seen_s: int  # seconds ago
    registered_s: int # seconds ago

    def __str__(self) -> str:
        return (f"[{self.status.upper():7s}] {self.agent_id}  "
                f"host={self.hostname}  ip={self.ip}  "
                f"last_seen={self.last_seen_s}s ago")


@dataclass
class HostResult:
    ip: str
    alive: bool = False
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)
    http_banner: str = ""
    is_ng_base: bool = False      # responded with NG headers or known endpoint
    in_fleet: bool = False
    fleet_agent_id: str = ""
    score: int = 0                # higher = more likely to be a probe

    def label(self) -> str:
        if not self.alive:
            return "DEAD"
        if self.in_fleet:
            return f"FLEET({self.fleet_agent_id})"
        if self.is_ng_base:
            return "NG-BASE?"
        return "UNKNOWN"


# ---------------------------------------------------------------------------
# Fleet loader
# ---------------------------------------------------------------------------

def load_fleet() -> tuple[list[FleetAgent], set[str]]:
    """Read fleet.json directly; return (agent_list, ip_set)."""
    if not FLEET_JSON.exists():
        return [], set()

    raw = json.loads(FLEET_JSON.read_text("utf-8"))
    agents: list[FleetAgent] = []
    ips: set[str] = set()
    now = time.time()

    for aid, data in raw.get("agents", {}).items():
        ls = data.get("last_seen", 0)
        reg = data.get("registered_at", 0)
        age = int(now - ls)
        reg_age = int(now - reg)
        status = "online" if age < 120 else ("stale" if age < 300 else "offline")
        ident = data.get("identity", {})
        ip = data.get("last_report", {}).get("local_ip", "")
        agents.append(FleetAgent(
            agent_id=aid,
            hostname=ident.get("hostname", "?"),
            ip=ip,
            status=status,
            last_seen_s=age,
            registered_s=reg_age,
        ))
        if ip:
            ips.add(ip)

    return agents, ips


# ---------------------------------------------------------------------------
# Subnet derivation
# ---------------------------------------------------------------------------

def derive_subnet(fleet_agents: list[FleetAgent], override: str | None) -> str:
    """Pick target subnet: explicit arg > fleet IPs > local interface."""
    if override:
        return override

    for agent in fleet_agents:
        ip = agent.ip
        if ip and not ip.startswith("127."):
            net = ipaddress.ip_interface(f"{ip}/24").network
            return str(net)

    # Fallback: local machine's primary IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_interface(f"{local_ip}/24").network
        return str(net)
    except Exception:
        return "192.168.1.0/24"


# ---------------------------------------------------------------------------
# Async ping
# ---------------------------------------------------------------------------

async def ping_host(ip: str, sem: asyncio.Semaphore) -> bool:
    """Return True if host responds to ping."""
    async with sem:
        flag = "-n" if platform.system() == "Windows" else "-c"
        cmd = ["ping", flag, "1", "-w", "500", ip] \
              if platform.system() == "Windows" \
              else ["ping", "-c", "1", "-W", "1", ip]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=2.5)
            return proc.returncode == 0
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Port check
# ---------------------------------------------------------------------------

async def check_port(ip: str, port: int) -> bool:
    """Return True if TCP port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=PORT_TIMEOUT
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HTTP banner grab
# ---------------------------------------------------------------------------

async def http_probe(ip: str, port: int) -> tuple[str, bool]:
    """Try an HTTP GET /  and return (banner_snippet, is_ng_base)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=HTTP_TIMEOUT
        )
        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {ip}:{port}\r\n"
            f"X-Requested-With: XMLHttpRequest\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        try:
            raw = await asyncio.wait_for(reader.read(2048), timeout=HTTP_TIMEOUT)
        except asyncio.TimeoutError:
            raw = b""

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        text = raw.decode("utf-8", errors="replace")
        banner = text[:300].replace("\r\n", " | ").replace("\n", " | ")

        # Heuristics: does this look like a Network Guardian base station?
        ng_signals = [
            "Network Guardian",
            "ng-probe",
            "wolfpak",
            "fleet",
            "X-NG-",
            "/api/fleet",
        ]
        is_ng = any(sig.lower() in text.lower() for sig in ng_signals)
        return banner, is_ng

    except Exception:
        return "", False


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Per-host full probe
# ---------------------------------------------------------------------------

async def probe_host(
    ip: str,
    fleet_ips: set[str],
    fleet_by_ip: dict[str, FleetAgent],
    ping_sem: asyncio.Semaphore,
) -> HostResult:
    result = HostResult(ip=ip)

    alive = await ping_host(ip, ping_sem)
    if not alive:
        return result

    result.alive = True

    # Hostname
    result.hostname = await asyncio.get_event_loop().run_in_executor(
        None, resolve_hostname, ip
    )

    # Fleet membership
    if ip in fleet_ips:
        result.in_fleet = True
        agent = fleet_by_ip.get(ip)
        if agent:
            result.fleet_agent_id = agent.agent_id

    # Open ports (parallel)
    port_checks = await asyncio.gather(*[check_port(ip, p) for p in PROBE_PORTS])
    result.open_ports = [p for p, open_ in zip(PROBE_PORTS, port_checks) if open_]

    # HTTP banner grab on any open probe port
    for port in result.open_ports:
        banner, is_ng = await http_probe(ip, port)
        if banner:
            result.http_banner = f":{port} — {banner[:120]}"
            if is_ng:
                result.is_ng_base = True
            break

    # Score: unregistered + active ports + NG fingerprint
    if not result.in_fleet:
        result.score += 5
    if result.open_ports:
        result.score += 3 * len(result.open_ports)
    if result.is_ng_base:
        result.score += 20
    if 8080 in result.open_ports:
        result.score += 5

    return result


# ---------------------------------------------------------------------------
# Fleet status checker — also poll the live /api/fleet/list endpoint
# ---------------------------------------------------------------------------

async def poll_fleet_api(base_url: str) -> list[dict]:
    """Try to pull a fresh agent list from the running dashboard."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                base_url.replace("http://", "").split(":")[0],
                int(base_url.split(":")[-1]),
            ),
            timeout=3.0,
        )
        host_port = base_url.replace("http://", "").replace("https://", "")
        req = (
            f"GET /api/fleet/list HTTP/1.0\r\n"
            f"Host: {host_port}\r\n"
            f"X-Requested-With: XMLHttpRequest\r\n"
            f"\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(65536), timeout=5.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        body = raw.decode("utf-8", errors="replace")
        # Strip HTTP headers
        if "\r\n\r\n" in body:
            body = body.split("\r\n\r\n", 1)[1]
        return json.loads(body).get("agents", [])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

async def main(subnet: str | None, base_url: str) -> None:
    print()
    print("=" * 68)
    print("  NETWORK GUARDIAN - Unregistered Probe Scanner")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 68)

    # ── Load fleet ─────────────────────────────────────────────────────
    fleet_agents, fleet_ips = load_fleet()
    fleet_by_ip: dict[str, FleetAgent] = {a.ip: a for a in fleet_agents if a.ip}

    print(f"\n[+] Fleet map ({len(fleet_agents)} registered agents):")
    if fleet_agents:
        for a in fleet_agents:
            print(f"    {a}")
    else:
        print("    (empty — no agents registered yet)")

    # ── Also try live API ──────────────────────────────────────────────
    print(f"\n[+] Polling dashboard API at {base_url} ...")
    live_agents = await poll_fleet_api(base_url)
    if live_agents:
        print(f"    Dashboard reports {len(live_agents)} agent(s):")
        for la in live_agents:
            print(f"      {la.get('agent_id','?')}  "
                  f"host={la.get('hostname','?')}  "
                  f"status={la.get('status','?')}")
        # Merge live IPs into fleet set
        for la in live_agents:
            lip = la.get("local_ip", "")
            if lip:
                fleet_ips.add(lip)
    else:
        print("    Dashboard not reachable or no agents reported — using fleet.json only")

    # ── Determine subnet ──────────────────────────────────────────────
    target_subnet = derive_subnet(fleet_agents, subnet)
    print(f"\n[+] Scanning subnet: {target_subnet}")
    network = ipaddress.ip_network(target_subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]
    print(f"    {len(hosts)} host addresses to check")

    # ── Ping sweep ────────────────────────────────────────────────────
    print(f"\n[+] Ping sweep (concurrency={PING_CONCURRENCY}) ...")
    t0 = time.monotonic()
    sem = asyncio.Semaphore(PING_CONCURRENCY)

    tasks = [probe_host(ip, fleet_ips, fleet_by_ip, sem) for ip in hosts]
    results: list[HostResult] = await asyncio.gather(*tasks)

    elapsed = time.monotonic() - t0
    alive_results = [r for r in results if r.alive]
    print(f"    Done in {elapsed:.1f}s — {len(alive_results)} host(s) alive")

    # ── Report ────────────────────────────────────────────────────────
    unregistered = [r for r in alive_results if not r.in_fleet]
    in_fleet     = [r for r in alive_results if r.in_fleet]

    print(f"\n{'-'*68}")
    print(f"  REGISTERED FLEET HOSTS FOUND ON NETWORK ({len(in_fleet)})")
    print(f"{'-'*68}")
    for r in sorted(in_fleet, key=lambda x: x.ip):
        ports_str = f"  ports={r.open_ports}" if r.open_ports else ""
        print(f"  {r.ip:16s}  {r.fleet_agent_id:14s}  {r.hostname}{ports_str}")

    print(f"\n{'-'*68}")
    print(f"  UNREGISTERED HOSTS (potential new probes) ({len(unregistered)})")
    print(f"{'-'*68}")

    if not unregistered:
        print("  None found — no unknown live hosts on the subnet.")
        print("  The new probe may not have connected yet. Try again in ~60s.")
    else:
        # Sort by score descending
        for r in sorted(unregistered, key=lambda x: -x.score):
            likely = " *** LIKELY PROBE ***" if r.score >= 10 else ""
            print(f"\n  IP:       {r.ip}{likely}")
            if r.hostname:
                print(f"  Hostname: {r.hostname}")
            if r.open_ports:
                print(f"  Ports:    {r.open_ports}")
            if r.is_ng_base:
                print(f"  NG Base:  YES — responded with Network Guardian fingerprint")
            if r.http_banner:
                print(f"  Banner:   {r.http_banner[:100]}")
            print(f"  Score:    {r.score}/35")

    # ── Guidance ─────────────────────────────────────────────────────
    print(f"\n{'-'*68}")
    print("  NEXT STEPS")
    print(f"{'-'*68}")
    if not unregistered:
        print("  • The probe hasn't checked in yet — wait ~60s and re-run.")
        print("  • Ask the employee to confirm the probe is running:")
        print("    python -m network_guardian.agent --base <base-url> --key <fleet-key>")
        print("  • Check that the probe has the correct fleet key and base URL.")
    else:
        for r in sorted(unregistered, key=lambda x: -x.score)[:3]:
            print(f"  • {r.ip} — monitor /api/fleet/list for registration from this IP.")
        print()
        print("  • If the probe is running but not registering, check:")
        print("    - Fleet key matches (NG_FLEET_KEY env var or --key flag)")
        print("    - Base URL is reachable from the probe's machine")
        print("    - Firewall allows outbound to port 8080 from the probe host")

    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan local subnet for NG probes not yet on the fleet map."
    )
    parser.add_argument(
        "--subnet", default=None,
        help="CIDR subnet to scan (e.g. 192.168.1.0/24). Auto-detected if omitted."
    )
    parser.add_argument(
        "--base", default=os.environ.get("NG_BASE", DEFAULT_BASE),
        help=f"Base station URL (default: {DEFAULT_BASE})"
    )
    args = parser.parse_args()

    asyncio.run(main(args.subnet, args.base))
