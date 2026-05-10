#!/usr/bin/env python3
"""
Network Guardian — MacBook Live Network Scan
=============================================
Scans your actual network interfaces, active connections, open ports,
and system metrics — then runs the Guardian's trained anomaly detectors
against the real data.

Usage:
    python mac_scan.py
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ── colours ──────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════╗
║         NETWORK GUARDIAN — MacBook Live Network Scan         ║
║                   Wolf-Pak Innovations LLC                   ║
╚══════════════════════════════════════════════════════════════╝{RESET}"""


# ── helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _section(title: str) -> None:
    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")


def _flag(label: str, value: str, anomalous: bool = False) -> None:
    colour = RED if anomalous else RESET
    print(f"  {colour}{label:<38} {value}{RESET}")


# ── 1. Network interfaces ─────────────────────────────────────────────────────

@dataclass
class Interface:
    name: str
    ip: str
    subnet: str
    mac: str = ""

def get_interfaces() -> list[Interface]:
    """Parse ifconfig to find active IPv4 interfaces."""
    out = _run(["ifconfig"])
    interfaces: list[Interface] = []
    current_if = ""
    for line in out.splitlines():
        m = re.match(r'^(\S+):', line)
        if m:
            current_if = m.group(1)
            continue
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+|\d+\.\d+\.\d+\.\d+)', line)
        if m and current_if and not current_if.startswith("lo"):
            ip = m.group(1)
            mask_raw = m.group(2)
            # Convert hex netmask → dotted
            if mask_raw.startswith("0x"):
                mask_int = int(mask_raw, 16)
                mask = socket.inet_ntoa(mask_int.to_bytes(4, "big"))
            else:
                mask = mask_raw
            try:
                net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                subnet = str(net)
            except ValueError:
                subnet = f"{ip}/24"
            interfaces.append(Interface(name=current_if, ip=ip, subnet=subnet))
    return interfaces


def get_gateway() -> str:
    out = _run(["netstat", "-rn"])
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return "unknown"


# ── 2. Active connections ─────────────────────────────────────────────────────

@dataclass
class Connection:
    proto: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str


def get_connections() -> list[Connection]:
    """Parse netstat -an for active TCP/UDP connections."""
    out = _run(["netstat", "-an", "-p", "tcp"])
    conns: list[Connection] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        if parts[0] not in ("tcp4", "tcp6", "tcp"):
            continue
        try:
            local = parts[3]
            remote = parts[4]
            state = parts[5] if len(parts) > 5 else ""

            def _parse_addr(addr: str):
                if addr.count(".") >= 4:
                    # dotted: a.b.c.d.port
                    idx = addr.rfind(".")
                    return addr[:idx], int(addr[idx+1:])
                elif ":" in addr:
                    idx = addr.rfind(":")
                    return addr[:idx], int(addr[idx+1:]) if addr[idx+1:] != "*" else 0
                return addr, 0

            lip, lport = _parse_addr(local)
            rip, rport = _parse_addr(remote)
            conns.append(Connection(
                proto="tcp", local_addr=lip, local_port=lport,
                remote_addr=rip, remote_port=rport, state=state,
            ))
        except (ValueError, IndexError):
            continue
    return conns


# ── 3. Listening ports ────────────────────────────────────────────────────────

def get_listening_ports() -> list[dict]:
    """lsof -iTCP -sTCP:LISTEN for listening services."""
    out = _run(["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"], timeout=15)
    services: list[dict] = []
    seen: set[int] = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        try:
            addr = parts[8]
            port = int(addr.rsplit(":", 1)[-1])
            if port not in seen:
                seen.add(port)
                services.append({
                    "process": parts[0],
                    "pid": parts[1],
                    "port": port,
                    "addr": addr,
                })
        except (ValueError, IndexError):
            continue
    return sorted(services, key=lambda x: x["port"])


# ── 4. Host discovery (ping sweep) ────────────────────────────────────────────

async def _ping_host(ip: str, sem: asyncio.Semaphore) -> tuple[str, bool]:
    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", "-t", "1", str(ip),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=2)
            return str(ip), proc.returncode == 0
        except (asyncio.TimeoutError, OSError):
            return str(ip), False


async def discover_hosts(subnet: str, max_hosts: int = 254) -> list[str]:
    """Ping-sweep the subnet. Caps at /24 range for speed."""
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return []

    hosts = list(net.hosts())[:max_hosts]
    sem = asyncio.Semaphore(50)
    tasks = [_ping_host(str(h), sem) for h in hosts]
    results = await asyncio.gather(*tasks)
    return [ip for ip, alive in results if alive]


# ── 5. System metrics ─────────────────────────────────────────────────────────

def get_system_metrics() -> dict[str, Any]:
    import os
    import shutil as _sh
    metrics: dict[str, Any] = {}

    # CPU load
    try:
        load = os.getloadavg()
        metrics["cpu_load_1m"]  = round(load[0], 2)
        metrics["cpu_load_5m"]  = round(load[1], 2)
        metrics["cpu_load_15m"] = round(load[2], 2)
    except OSError:
        metrics["cpu_load_1m"] = 0.0

    # Memory (vm_stat on macOS)
    vm = _run(["vm_stat"])
    page_size = 16384  # Apple Silicon default
    m = re.search(r"page size of (\d+)", vm)
    if m:
        page_size = int(m.group(1))
    free = wired = active = inactive = 0
    for label, attr in [("Pages free", "free"), ("Pages wired down", "wired"),
                         ("Pages active", "active"), ("Pages inactive", "inactive")]:
        mm = re.search(rf"{label}:\s+(\d+)", vm)
        if mm:
            val = int(mm.group(1)) * page_size / (1024**3)
            if attr == "free":     free = val
            elif attr == "wired":  wired = val
            elif attr == "active": active = val
            else:                  inactive = val
    total_gb = wired + active + inactive + free
    used_gb  = wired + active
    metrics["mem_total_gb"]  = round(total_gb, 2)
    metrics["mem_used_gb"]   = round(used_gb, 2)
    metrics["mem_free_gb"]   = round(free, 2)
    metrics["mem_usage_pct"] = round(used_gb / total_gb * 100, 1) if total_gb > 0 else 0.0

    # Disk
    usage = _sh.disk_usage("/")
    metrics["disk_total_gb"]  = round(usage.total / (1024**3), 2)
    metrics["disk_used_gb"]   = round(usage.used  / (1024**3), 2)
    metrics["disk_free_gb"]   = round(usage.free  / (1024**3), 2)
    metrics["disk_usage_pct"] = round(usage.used  / usage.total * 100, 1)

    # Network byte counters via netstat -ib
    nb = _run(["netstat", "-ib"])
    bytes_in = bytes_out = packets_in = packets_out = 0
    for line in nb.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 10 and parts[0].startswith("en"):
            try:
                bytes_in    += int(parts[6])
                bytes_out   += int(parts[9])
                packets_in  += int(parts[4])
                packets_out += int(parts[7])
            except (ValueError, IndexError):
                pass
    metrics["net_bytes_in"]    = bytes_in
    metrics["net_bytes_out"]   = bytes_out
    metrics["net_packets_in"]  = packets_in
    metrics["net_packets_out"] = packets_out

    return metrics


# ── 6. Build feature vectors from real connection data ────────────────────────

def connections_to_feature_vectors(conns: list[Connection]) -> list[list[float]]:
    """
    Convert live connections to 8-feature vectors matching the training schema:
    [bytes_sent, bytes_recv, packets, duration_ms, dst_port,
     protocol_flag, conn_rate, error_rate]

    Since we can't measure bytes/duration from netstat alone, we use
    port-based heuristics for a realistic approximation.
    """
    vectors: list[list[float]] = []
    established = [c for c in conns if c.state == "ESTABLISHED" and c.remote_port > 0]

    # Count connections per remote IP for conn_rate approximation
    remote_counts: dict[str, int] = {}
    for c in established:
        remote_counts[c.remote_addr] = remote_counts.get(c.remote_addr, 0) + 1

    for c in established:
        rport = c.remote_port
        lport = c.local_port

        # Heuristic bytes_sent/recv based on port type
        if rport in (80, 8080):       # HTTP
            bsent, brecv = 2500.0, 12000.0; pkt = 35.0
        elif rport in (443, 8443):    # HTTPS
            bsent, brecv = 4000.0, 15000.0; pkt = 55.0
        elif rport == 53:             # DNS
            bsent, brecv = 80.0, 200.0;   pkt = 3.0
        elif rport in (22,):          # SSH
            bsent, brecv = 1200.0, 1200.0; pkt = 20.0
        elif rport > 49152:           # ephemeral / unknown
            bsent, brecv = 1000.0, 1000.0; pkt = 15.0
        elif rport in (4444, 5555, 1337, 31337, 6667):  # suspicious C2-like
            bsent, brecv = 80000.0, 200.0; pkt = 800.0
        elif rport in (445, 3389, 6379, 27017, 5900):   # sensitive services
            bsent, brecv = 30000.0, 500.0; pkt = 400.0
        else:
            bsent, brecv = 3000.0, 8000.0; pkt = 40.0

        conn_rate = float(remote_counts.get(c.remote_addr, 1))
        # error_rate approximation: TIME_WAIT and CLOSE_WAIT suggest errors
        error_rate = 0.05 if c.state in ("TIME_WAIT", "CLOSE_WAIT") else 0.01

        vectors.append([
            bsent,          # bytes_sent
            brecv,          # bytes_recv
            pkt,            # packets
            200.0,          # duration_ms (unknown from netstat)
            float(rport),   # dst_port
            0.0,            # protocol_flag (0=TCP)
            conn_rate,      # conn_rate
            error_rate,     # error_rate
        ])

    return vectors


# ── 7. Suspicious port classification ────────────────────────────────────────

KNOWN_GOOD_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    8080, 8443, 3000, 3306, 5432, 5900, 8888,
}

SUSPICIOUS_PORTS = {
    4444, 5555, 1337, 31337, 6667, 6668, 6669,  # C2/RAT
    9001, 9030,                                   # Tor
    1080, 3128, 8118,                             # proxy
    445, 137, 138, 139,                          # SMB (unusual outbound)
    23, 69, 512, 513, 514,                        # telnet/tftp/rsh
}


def classify_port(port: int) -> str:
    if port in SUSPICIOUS_PORTS:
        return "SUSPICIOUS"
    if port < 1024:
        return "WELL_KNOWN"
    if port > 49152:
        return "EPHEMERAL"
    return "REGISTERED"


# ── 8. Anomaly detection ──────────────────────────────────────────────────────

def run_anomaly_detection(vectors: list[list[float]]) -> list[dict]:
    """Train the Guardian's ensemble on synthetic normal data, score real vectors."""
    from network_guardian.ai.anomaly import IsolationForest, OneClassSVM, EnsembleDetector
    from network_guardian.ai.datasets import NetworkTrafficGenerator

    # Generate synthetic normal training data (800 normal samples)
    gen = NetworkTrafficGenerator(seed=42)
    dataset = gen.generate(n_normal=800, n_anomaly=0, n_attack=0, n_scan=0)
    normal_data = dataset.feature_matrix()

    # Fit detectors on normal-only data
    iso  = IsolationForest(n_trees=100, max_samples=256, threshold=0.50, seed=42)
    svm  = OneClassSVM(nu=0.1, seed=42)
    ens  = EnsembleDetector([iso, svm], threshold=0.50)

    iso.fit(normal_data)
    svm.fit(normal_data)

    results = []
    for vec in vectors:
        iso_score = iso.score(vec)
        svm_score = svm.score(vec)
        ens_score = ens.score(vec)
        results.append({
            "vector": vec,
            "isolation_forest": iso_score,
            "one_class_svm":    svm_score,
            "ensemble":         ens_score,
            "flagged": iso_score.is_anomaly or svm_score.is_anomaly or ens_score.is_anomaly,
        })
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    print(BANNER)
    print(f"\n  Scan started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # ── Interfaces ────────────────────────────────────────────────────────────
    _section("1. NETWORK INTERFACES")
    interfaces = get_interfaces()
    gateway    = get_gateway()

    if not interfaces:
        print(f"  {YELLOW}No active interfaces found.{RESET}")
    for iface in interfaces:
        print(f"  {GREEN}●{RESET} {iface.name:<10}  IP: {iface.ip:<18}  Subnet: {iface.subnet}")
    print(f"  {'Gateway':<12}  {gateway}")

    # Pick primary interface (prefer en0)
    primary = next((i for i in interfaces if i.name == "en0"), None) or \
              (interfaces[0] if interfaces else None)

    # ── System metrics ────────────────────────────────────────────────────────
    _section("2. SYSTEM METRICS")
    metrics = get_system_metrics()

    cpu_high  = metrics.get("cpu_load_1m", 0) > 4.0
    mem_high  = metrics.get("mem_usage_pct", 0) > 85.0
    disk_high = metrics.get("disk_usage_pct", 0) > 90.0

    _flag("CPU Load  (1m / 5m / 15m)",
          f"{metrics.get('cpu_load_1m',0):.2f} / {metrics.get('cpu_load_5m',0):.2f} / {metrics.get('cpu_load_15m',0):.2f}",
          cpu_high)
    _flag("Memory Usage",
          f"{metrics.get('mem_used_gb',0):.1f} GB / {metrics.get('mem_total_gb',0):.1f} GB  ({metrics.get('mem_usage_pct',0):.1f}%)",
          mem_high)
    _flag("Disk Usage  (/)",
          f"{metrics.get('disk_used_gb',0):.1f} GB / {metrics.get('disk_total_gb',0):.1f} GB  ({metrics.get('disk_usage_pct',0):.1f}%)",
          disk_high)
    _flag("Net Bytes   (in / out)",
          f"{metrics.get('net_bytes_in',0)/1e6:.1f} MB  /  {metrics.get('net_bytes_out',0)/1e6:.1f} MB")

    alerts_metrics = []
    if cpu_high:  alerts_metrics.append(f"High CPU load: {metrics.get('cpu_load_1m',0):.2f}")
    if mem_high:  alerts_metrics.append(f"High memory: {metrics.get('mem_usage_pct',0):.1f}%")
    if disk_high: alerts_metrics.append(f"Critical disk: {metrics.get('disk_usage_pct',0):.1f}%")

    # ── Listening ports ───────────────────────────────────────────────────────
    _section("3. LISTENING SERVICES (open ports on this Mac)")
    services  = get_listening_ports()
    sus_ports = []
    if not services:
        print(f"  {YELLOW}Could not enumerate listening ports (try: sudo python mac_scan.py){RESET}")
    for svc in services:
        port      = svc["port"]
        cls       = classify_port(port)
        anomalous = cls == "SUSPICIOUS"
        if anomalous:
            sus_ports.append(svc)
        colour = RED if anomalous else (YELLOW if cls == "REGISTERED" else RESET)
        tag    = f" {RED}◄ SUSPICIOUS{RESET}" if anomalous else ""
        print(f"  {colour}Port {port:<6}  {svc['process']:<20} PID {svc['pid']}{tag}{RESET}")

    if not services:
        print(f"  (run with sudo for full port list)")

    # ── Active connections ────────────────────────────────────────────────────
    _section("4. ACTIVE CONNECTIONS")
    conns       = get_connections()
    established = [c for c in conns if c.state == "ESTABLISHED"]
    time_wait   = [c for c in conns if c.state == "TIME_WAIT"]

    print(f"  Total connections:         {len(conns)}")
    print(f"  Established:               {len(established)}")
    print(f"  TIME_WAIT:                 {len(time_wait)}")

    # Check for suspicious outbound ports
    sus_conns = [c for c in established
                 if c.remote_port in SUSPICIOUS_PORTS
                 and not c.remote_addr.startswith("127.")]

    if sus_conns:
        print(f"\n  {RED}{BOLD}⚠  SUSPICIOUS OUTBOUND CONNECTIONS:{RESET}")
        for c in sus_conns:
            print(f"  {RED}  {c.local_addr}:{c.local_port} → {c.remote_addr}:{c.remote_port}  [{c.state}]{RESET}")
    else:
        print(f"\n  {GREEN}No suspicious outbound ports detected.{RESET}")

    # Show unique remote IPs (external only)
    external = [c for c in established if not c.remote_addr.startswith(("127.", "::1", "*"))]
    remote_ips: dict[str, list[int]] = {}
    for c in external:
        remote_ips.setdefault(c.remote_addr, []).append(c.remote_port)

    if remote_ips:
        print(f"\n  Active external connections ({len(remote_ips)} remote IPs):")
        for ip, ports in sorted(remote_ips.items())[:20]:
            cls = classify_port(min(ports))
            colour = RED if any(p in SUSPICIOUS_PORTS for p in ports) else RESET
            print(f"  {colour}  {ip:<40} ports: {sorted(set(ports))}{RESET}")

    # ── Host discovery ────────────────────────────────────────────────────────
    _section("5. HOST DISCOVERY  (ping sweep)")
    if primary:
        print(f"  Sweeping {primary.subnet} ...")
        t0    = time.perf_counter()
        alive = await discover_hosts(primary.subnet)
        elapsed = time.perf_counter() - t0
        print(f"  Found {len(alive)} live host(s) in {elapsed:.1f}s\n")
        for host_ip in sorted(alive, key=lambda x: tuple(int(p) for p in x.split("."))):
            marker = f"  {GREEN}◄ this Mac{RESET}" if host_ip == primary.ip else ""
            gwmark = f"  {CYAN}◄ gateway{RESET}" if host_ip == gateway else ""
            print(f"  {GREEN}●{RESET} {host_ip}{marker}{gwmark}")
    else:
        alive = []
        print(f"  {YELLOW}No primary interface found, skipping host discovery.{RESET}")

    # ── Anomaly detection ─────────────────────────────────────────────────────
    _section("6. ML ANOMALY DETECTION  (Guardian AI)")
    vectors = connections_to_feature_vectors(conns)

    if not vectors:
        print(f"  {YELLOW}No ESTABLISHED connections to analyse.{RESET}")
        anomaly_results = []
    else:
        print(f"  Analysing {len(vectors)} active connection(s) ...\n")
        anomaly_results = run_anomaly_detection(vectors)

        flagged = [r for r in anomaly_results if r["flagged"]]
        print(f"  IsolationForest flags:  {sum(1 for r in anomaly_results if r['isolation_forest'].is_anomaly)}/{len(anomaly_results)}")
        print(f"  OneClassSVM flags:      {sum(1 for r in anomaly_results if r['one_class_svm'].is_anomaly)}/{len(anomaly_results)}")
        print(f"  Ensemble flags:         {sum(1 for r in anomaly_results if r['ensemble'].is_anomaly)}/{len(anomaly_results)}")

        if flagged:
            print(f"\n  {RED}{BOLD}⚠  ANOMALOUS CONNECTIONS DETECTED:{RESET}")
            # Map vectors back to connections for context
            established_list = [c for c in conns if c.state == "ESTABLISHED" and c.remote_port > 0]
            for i, r in enumerate(anomaly_results):
                if not r["flagged"]:
                    continue
                conn = established_list[i] if i < len(established_list) else None
                score = r["ensemble"].score
                methods = []
                if r["isolation_forest"].is_anomaly: methods.append("IF")
                if r["one_class_svm"].is_anomaly:    methods.append("SVM")
                if r["ensemble"].is_anomaly:         methods.append("ENS")
                conn_str = f"{conn.remote_addr}:{conn.remote_port}" if conn else f"vec[{i}]"
                print(f"  {RED}  [{'/'.join(methods)}] score={score:.3f}  {conn_str}{RESET}")
        else:
            print(f"\n  {GREEN}All connections appear normal.{RESET}")

    # ── Summary ───────────────────────────────────────────────────────────────
    _section("SCAN SUMMARY")

    total_alerts = len(alerts_metrics) + len(sus_ports) + len(sus_conns)
    anomaly_count = sum(1 for r in anomaly_results if r["flagged"]) if anomaly_results else 0
    total_alerts += anomaly_count

    if total_alerts == 0:
        status_colour = GREEN
        status_text   = "CLEAN — No threats detected"
    elif total_alerts <= 2:
        status_colour = YELLOW
        status_text   = f"CAUTION — {total_alerts} issue(s) found"
    else:
        status_colour = RED
        status_text   = f"ALERT — {total_alerts} issue(s) found"

    print(f"\n  {BOLD}{status_colour}{status_text}{RESET}\n")

    all_alerts = alerts_metrics + \
        [f"Suspicious listening port: {s['port']} ({s['process']})" for s in sus_ports] + \
        [f"Suspicious outbound: {c.remote_addr}:{c.remote_port}" for c in sus_conns]

    if all_alerts:
        print(f"  {YELLOW}Issues:{RESET}")
        for a in all_alerts:
            print(f"    {YELLOW}▸ {a}{RESET}")
    if anomaly_count:
        print(f"    {RED}▸ {anomaly_count} connection(s) flagged as anomalous by ML engine{RESET}")

    print(f"\n  Scan completed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Hosts found: {len(alive)}  |  Connections: {len(conns)}  |  Listening ports: {len(services)}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
