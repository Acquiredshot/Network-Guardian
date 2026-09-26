#!/usr/bin/env python3
# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
push_mask_events.py — pushes MASK-style host observation events to the
Network Guardian Event Fabric intake endpoint.

This is the adapter that would be embedded in MASK's bridge (or called by
maskd periodically) to forward host observations into the Wolf-Pak platform.

Usage:
    python push_mask_events.py [--url URL] [--count N]

Default URL: http://127.0.0.1:8080/api/event-fabric/intake
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("push_mask_events")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def post_intake(url: str, envelope: dict[str, Any]) -> dict[str, Any] | None:
    """POST a single CrossAppEnvelope to the NG intake endpoint."""
    try:
        resp = requests.post(url, json=envelope, timeout=10)
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            logger.info("  OK row=%s nodes=%s", data.get("row_id"), data.get("graph_nodes"))
            return data
        logger.warning("  FAIL status=%d body=%s", resp.status_code, data)
        return None
    except requests.ConnectionError:
        logger.error("  Cannot connect to %s — is the dashboard running?", url)
        return None
    except Exception as exc:
        logger.error("  Request failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Event generators (mirrors of MASK's ring-buffer observations)
# ---------------------------------------------------------------------------

def make_sysinfo_envelope(asset_id: str, hostname: str) -> dict[str, Any]:
    """System info event — mirrors mask_get_sysinfo()."""
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "MASK",
        "source_version": "0.3.0",
        "event_type": "sysinfo_observation",
        "severity": "info",
        "category": "system",
        "description": f"System info for {hostname}",
        "payload": {
            "native_id": f"sysinfo-{asset_id}",
            "hostname": hostname,
            "os": "Windows 11 Pro",
            "uptime_minutes": 3821,
            "cpu_cores": 8,
            "total_memory_gb": 32,
            "hostname_fqdn": f"{hostname}.local",
        },
    }


def make_process_envelope(asset_id: str, hostname: str) -> dict[str, Any]:
    """Process list event — mirrors mask_list_processes()."""
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "MASK",
        "source_version": "0.3.0",
        "event_type": "process_observation",
        "severity": "info",
        "category": "process",
        "description": f"Active processes on {hostname}",
        "payload": {
            "native_id": f"procs-{asset_id}",
            "hostname": hostname,
            "processes": [
                {"pid": 3824, "name": "python.exe", "user": "cody", "cmdline": "python -m network_guardian"},
                {"pid": 3840, "name": "chrome.exe", "user": "cody", "cmdline": "chrome --type=broker"},
                {"pid": 3912, "name": "nginx.exe", "user": "system", "cmdline": "nginx: worker process"},
                {"pid": 4021, "name": "svchost.exe", "user": "SYSTEM", "cmdline": "Services: WinRM"},
                {"pid": 4110, "name": "code.exe", "user": "cody", "cmdline": "code.exe --type=renderer"},
                {"pid": 4188, "name": "slack.exe", "user": "cody", "cmdline": "slack.exe"},
                {"pid": 4220, "name": "powershell.exe", "user": "cody", "cmdline": "pwsh -NoProfile"},
            ],
        },
    }


def make_network_envelope(asset_id: str, hostname: str) -> dict[str, Any]:
    """Network connection event — mirrors mask_list_connections()."""
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "MASK",
        "source_version": "0.3.0",
        "event_type": "network_connection_observation",
        "severity": "medium",
        "category": "network",
        "description": f"Active network connections on {hostname}",
        "payload": {
            "native_id": f"net-{asset_id}",
            "hostname": hostname,
            "connections": [
                {"local_address": f"{asset_id}", "local_port": 8080, "remote_address": "192.168.1.1", "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED", "pid": 3824},
                {"local_address": f"{asset_id}", "local_port": 22, "remote_address": "10.0.0.5", "remote_port": 54321, "protocol": "TCP", "state": "ESTABLISHED", "pid": 4021},
                {"local_address": f"{asset_id}", "local_port": 0, "remote_address": "142.250.1.1", "remote_port": 80, "protocol": "TCP", "state": "TIME_WAIT", "pid": 4110},
                {"local_address": f"{asset_id}", "local_port": 5353, "remote_address": "224.0.0.251", "remote_port": 5353, "protocol": "UDP", "state": "ESTABLISHED", "pid": 3840},
                {"local_address": f"{asset_id}", "local_port": 49660, "remote_address": "192.168.1.254", "remote_port": 67, "protocol": "UDP", "state": "ESTABLISHED", "pid": 4220},
            ],
        },
    }


def make_auth_envelope(asset_id: str, hostname: str) -> dict[str, Any]:
    """User session event — mirrors mask_enum_users()."""
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "MASK",
        "source_version": "0.3.0",
        "event_type": "user_sessions",
        "severity": "low",
        "category": "auth",
        "description": f"Currently logged-in users on {hostname}",
        "payload": {
            "native_id": f"sessions-{asset_id}",
            "hostname": hostname,
            "sessions": [
                {"user": "cody", "terminal": "pts/0", "login_time_ms": now_ms() - 3600000, "from_host": "localhost"},
                {"user": "admin", "terminal": "pts/1", "login_time_ms": now_ms() - 7200000, "from_host": "192.168.1.50"},
                {"user": "SYSTEM", "terminal": "-", "login_time_ms": now_ms() - 86400000, "from_host": "N/A"},
            ],
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

EVENT_TYPES = [
    ("sysinfo", make_sysinfo_envelope),
    ("process", make_process_envelope),
    ("network", make_network_envelope),
    ("auth", make_auth_envelope),
]


def run(url: str, count: int, asset_id: str, hostname: str) -> int:
    """Push *count* batches (4 event types each) and report."""
    ok = 0
    for batch in range(count):
        for label, make_fn in EVENT_TYPES:
            env = make_fn(asset_id, hostname)
            env["description"] = f"{label} batch-{batch} on {hostname}"
            result = post_intake(url, env)
            if result:
                ok += 1
            # Small stagger between pushes so they don't all batch at once
            time.sleep(0.05)
        logger.info("Batch %d complete (%d/%d types OK)", batch + 1, ok, (batch + 1) * len(EVENT_TYPES))
        time.sleep(0.2)
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description="Push MASK-style host observations to NG Event Fabric")
    ap.add_argument("--url", default="http://127.0.0.1:8080/api/event-fabric/intake",
                    help="NG intake endpoint URL (default: %(default)s)")
    ap.add_argument("--count", type=int, default=3,
                    help="Number of batches to push (default: %(default)s)")
    ap.add_argument("--asset-id", default="mask-host-codyc-wkstn-01",
                    help="Asset ID to use (default: %(default)s)")
    ap.add_argument("--hostname", default="mask-host-codyc-wkstn-01",
                    help="Hostname to embed (default: %(default)s)")
    ap.add_argument("--once", action="store_true",
                    help="Push a single batch and exit (for quick smoke test)")
    args = ap.parse_args()

    logger.info("Pushing MASK observations to %s — asset=%s hostname=%s",
                args.url, args.asset_id, args.hostname)

    count = 1 if args.once else args.count
    ok = run(args.url, count, args.asset_id, args.hostname)
    total = count * len(EVENT_TYPES)
    logger.info("Done: %d/%d events accepted", ok, total)

    if ok < total:
        logger.warning("Some events were rejected — check dashboard logs")
        sys.exit(1)


if __name__ == "__main__":
    main()
