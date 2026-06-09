#!/usr/bin/env python3
# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
flood_watchdog.py — Standalone Network Flood Watchdog

Monitors active TCP/UDP connections and automatically blocks source IPs
that exceed the configured threshold.

Launched by harden_machine.ps1:
    python flood_watchdog.py --threshold 60 --interval 5

Can also be run standalone:
    python flood_watchdog.py --threshold 60 --interval 5 --firewall

When a flood is detected the watchdog:
  1. Logs it to console with timestamp
  2. Notifies the Network Guardian dashboard API (if running) to trigger IPS block
  3. Optionally adds a Windows Firewall inbound block rule (requires admin)

Dependencies: standard library only. psutil is used if available and
falls back to netstat subprocess if not.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FloodWatchdog] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("flood_watchdog")


# ---------------------------------------------------------------------------
# Connection gathering (psutil preferred, netstat fallback)
# ---------------------------------------------------------------------------

def _get_connections_psutil() -> list[tuple[str, int]]:
    """Return (remote_ip, remote_port) pairs via psutil."""
    import psutil
    result: list[tuple[str, int]] = []
    for conn in psutil.net_connections(kind="inet"):
        raddr = getattr(conn, "raddr", None)
        if raddr and getattr(raddr, "ip", None):
            ip = raddr.ip
            # Skip loopback
            if not ip.startswith("127.") and ip != "::1":
                result.append((ip, getattr(raddr, "port", 0)))
    return result


def _get_connections_netstat() -> list[tuple[str, int]]:
    """Return (remote_ip, remote_port) pairs via netstat subprocess."""
    result: list[tuple[str, int]] = []
    try:
        cmd = (
            ["netstat", "-n", "-p", "TCP"]
            if platform.system() == "Windows"
            else ["netstat", "-tn"]
        )
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and "ESTABLISHED" in parts[-1].upper():
                remote = parts[2]
                if ":" in remote:
                    ip, _, port_str = remote.rpartition(":")
                    ip = ip.strip("[]")
                    if not ip.startswith("127.") and ip != "::1":
                        try:
                            result.append((ip, int(port_str)))
                        except ValueError:
                            pass
    except Exception as e:
        logger.debug("netstat error: %s", e)
    return result


def get_connections() -> list[tuple[str, int]]:
    """Get active connections, preferring psutil over netstat."""
    try:
        import psutil  # noqa: F401
        return _get_connections_psutil()
    except ImportError:
        return _get_connections_netstat()


# ---------------------------------------------------------------------------
# Actions on detection
# ---------------------------------------------------------------------------

def _notify_dashboard(source_ip: str, reason: str, port: int) -> bool:
    """POST a block request to the running Network Guardian dashboard API."""
    url     = f"http://127.0.0.1:{port}/api/ips/block"
    payload = json.dumps({
        "ip":          source_ip,
        "reason":      "flood_watchdog",
        "description": reason,
        "duration":    3600,
    }).encode()
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def _add_windows_firewall_rule(ip: str) -> bool:
    """Add a Windows Firewall inbound block rule for the offending IP."""
    if platform.system() != "Windows":
        return False
    rule_name = f"NG-FloodBlock-{ip.replace('.', '-').replace(':', '-')}"
    try:
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
            ],
            check=True, capture_output=True, timeout=10,
        )
        logger.info("Windows Firewall rule added: block inbound from %s", ip)
        return True
    except subprocess.CalledProcessError as e:
        logger.debug("Could not add firewall rule (need admin?): %s", e)
        return False


def _add_macos_pf_rule(ip: str) -> bool:
    """
    Block an IP on macOS using pfctl's ng_flood_block table.
    Requires admin/sudo. The table must be anchored in /etc/pf.conf or
    an active anchor to persist across reboots; this call adds to the
    in-memory table so the block is effective immediately.
    """
    if platform.system() != "Darwin":
        return False
    try:
        subprocess.run(
            ["pfctl", "-t", "ng_flood_block", "-T", "add", ip],
            check=True, capture_output=True, timeout=10,
        )
        logger.info("macOS pfctl: blocked inbound from %s via ng_flood_block table", ip)
        return True
    except FileNotFoundError:
        logger.debug("pfctl not found — skipping macOS firewall rule")
        return False
    except subprocess.CalledProcessError as e:
        logger.debug(
            "Could not add pfctl rule (need sudo? table not defined in pf.conf?): %s", e
        )
        return False


# ---------------------------------------------------------------------------
# Main watchdog loop
# ---------------------------------------------------------------------------

def run(threshold: int, interval: float, dashboard_port: int, use_firewall: bool) -> None:
    logger.info(
        "Flood Watchdog started — threshold=%d conns/IP  interval=%.0fs  "
        "dashboard=:%d  firewall=%s",
        threshold, interval, dashboard_port, use_firewall,
    )

    blocked_ips: set[str] = set()

    while True:
        conns = get_connections()
        count_per_ip: dict[str, int] = defaultdict(int)
        for ip, _ in conns:
            count_per_ip[ip] += 1

        for ip, count in count_per_ip.items():
            if ip in blocked_ips:
                continue
            if count >= threshold:
                ts     = datetime.now(timezone.utc).isoformat()
                reason = (
                    f"Flood watchdog: {count} simultaneous connections from {ip} "
                    f"(threshold={threshold}) at {ts}"
                )
                logger.warning(
                    "FLOOD DETECTED  ip=%-18s  connections=%d  threshold=%d",
                    ip, count, threshold,
                )

                # Notify the Network Guardian dashboard
                if _notify_dashboard(ip, reason, dashboard_port):
                    logger.info("Dashboard notified — IPS block requested for %s", ip)
                else:
                    logger.warning(
                        "Dashboard not reachable on :%d — could not request block for %s",
                        dashboard_port, ip,
                    )

                # Optional native firewall rule (requires admin elevation)
                if use_firewall:
                    if not _add_windows_firewall_rule(ip):
                        _add_macos_pf_rule(ip)

                blocked_ips.add(ip)

        # Global connection table exhaustion warning
        total = len(conns)
        if total >= 800:
            logger.warning(
                "CONNECTION TABLE WARNING: %d total active connections — "
                "router NAT exhaustion risk. Check for active flood/scan tools.",
                total,
            )

        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Guardian Flood Watchdog — monitors connections and blocks floods",
    )
    parser.add_argument(
        "--threshold", type=int, default=60,
        help="Connections from a single IP before blocking (default: 60)",
    )
    parser.add_argument(
        "--interval", type=float, default=5.0,
        help="Polling interval in seconds (default: 5)",
    )
    parser.add_argument(
        "--port", type=int, default=8081,
        help="Network Guardian dashboard port (default: 8081)",
    )
    parser.add_argument(
        "--firewall", action="store_true",
        help="Also add a native OS firewall block rule for flood sources "
             "(Windows: netsh advfirewall; macOS: pfctl — both require admin elevation)",
    )
    args = parser.parse_args()

    try:
        run(args.threshold, args.interval, args.port, args.firewall)
    except KeyboardInterrupt:
        logger.info("Flood Watchdog stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
