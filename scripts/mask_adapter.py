#!/usr/bin/env python3
# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
mask_adapter.py — exports MASK daemon observations as structured events
into the Wolf-Pak Event Fabric.

CURRENT STATE: The MASK daemon (maskd) is a C single-host monitor on Linux.
This adapter either:
  (A) Talks to maskd's JSON IPC on port 7717 (when the daemon is running),
      requesting sysinfo, network_connections, and process_observation; or
  (B) On Windows / when maskd is unavailable, falls back to direct
      observation via native OS commands (psutil, netstat, who) so the
      Event Fabric still receives host telemetry from this host.

Each observation is wrapped in the CrossAppEnvelope schema and POSTed to
the Network Guardian dashboard intake endpoint.

Usage:
    python mask_adapter.py [--url URL] [--interval SEC] [--once]

Default URL: http://127.0.0.1:8080/api/event-fabric/intake
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

import requests

from network_guardian.core.events import CrossAppEnvelope

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("mask_adapter")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def post_event(url: str, envelope: CrossAppEnvelope) -> dict[str, Any] | None:
    try:
        resp = requests.post(
            url,
            json=envelope.to_dict(),
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            logger.info(
                "  stored row=%s nodes=%s source=%s type=%s",
                data.get("row_id"),
                data.get("graph_nodes"),
                envelope.source,
                envelope.event_type,
            )
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
# MASK IPC client (live daemon path)
# ---------------------------------------------------------------------------

MASK_ASSET_ID = os.environ.get("MASK_ASSET_ID", "mask-host-local")
MASK_IPC_HOST = os.environ.get("MASK_IPC_HOST", "127.0.0.1")
MASK_IPC_PORT = int(os.environ.get("MASK_IPC_PORT", "7717"))


def send_ipc(command: dict[str, Any]) -> dict[str, Any] | None:
    """Send one JSON command to maskd's IPC and return the parsed reply."""
    try:
        sock = socket.create_connection((MASK_IPC_HOST, MASK_IPC_PORT), timeout=3)
        sock.sendall((json.dumps(command) + "\n").encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        # The daemon sends one JSON line per response
        line = data.decode(errors="replace").strip().split("\n")[-1]
        return json.loads(line)
    except (socket.timeout, ConnectionRefusedError, OSError, json.JSONDecodeError) as exc:
        logger.debug("maskd IPC unavailable: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Observation functions
# ---------------------------------------------------------------------------

def observe_sysinfo_mask() -> dict[str, Any] | None:
    """Ask maskd for sysinfo via IPC."""
    reply = send_ipc({"tool": "sysinfo", "args": {}})
    if reply and isinstance(reply, dict) and "payload" in reply:
        return reply["payload"]
    return None


def observe_sysinfo_fallback() -> dict[str, Any]:
    """Fallback: read host metrics directly (works on Linux and Windows)."""
    payload: dict[str, Any] = {"source": "mask_adapter_fallback"}
    if psutil:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        payload["load1"] = cpu / 100.0
        payload["load5"] = cpu / 100.0
        payload["load15"] = cpu / 100.0
        payload["mem_total_kb"] = int(mem.total / 1024)
        payload["mem_available_kb"] = int(mem.available / 1024)
    else:
        # Best-effort via os
        payload["load1"] = 0.0
        payload["mem_total_kb"] = 0
        payload["mem_available_kb"] = 0
    payload["hostname"] = os.environ.get("HOSTNAME", "mask-host-local")
    return payload


def observe_network_mask() -> dict[str, Any] | None:
    """Ask maskd for network connections via IPC (tool_net_connections)."""
    reply = send_ipc({"tool": "net_connections", "args": {"proto": "tcp"}})
    if reply and isinstance(reply, dict) and "payload" in reply:
        return reply["payload"]
    return None


def observe_network_fallback() -> dict[str, Any]:
    """Fallback: enumerate TCP connections via psutil or netstat."""
    payload: dict[str, Any] = {"source": "mask_adapter_fallback"}
    connections: list[dict[str, Any]] = []
    if psutil:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_ESTABLISHED:
                continue
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            except Exception:
                continue
            connections.append({
                "proto": "tcp",
                "state": conn.status,
                "local_address": laddr,
                "remote_address": raddr,
                "pid": conn.pid,
            })
    else:
        # Fallback via netstat
        try:
            proc = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=10
            )
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "ESTABLISHED":
                    connections.append({
                        "proto": "tcp",
                        "state": "ESTABLISHED",
                        "local_address": parts[1],
                        "remote_address": parts[2],
                        "pid": int(parts[-1]) if parts[-1].isdigit() else 0,
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    payload["connections"] = connections[:50]  # bound
    payload["hostname"] = os.environ.get("HOSTNAME", "unknown")
    return payload


def observe_processes_mask() -> dict[str, Any] | None:
    """Ask maskd for process list via IPC (tool_asset or custom tool)."""
    # maskd's tool_asset.c may provide process info; try it
    reply = send_ipc({"tool": "asset", "args": {"type": "processes"}})
    if reply and isinstance(reply, dict) and "payload" in reply:
        return reply["payload"]
    # Fall back to a generic process query if the daemon has a shell tool
    reply = send_ipc({"tool": "run_shell", "args": {"command": "ps -eo pid,comm,user --no-headers"}})
    if reply and isinstance(reply, dict) and "output" in reply:
        return {"raw_ps_output": reply["output"], "source": "maskd_run_shell"}
    return None


def observe_processes_fallback() -> dict[str, Any]:
    """Fallback: list processes via psutil or ps."""
    payload: dict[str, Any] = {"source": "mask_adapter_fallback"}
    processes: list[dict[str, Any]] = []
    if psutil:
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                info = proc.info
                processes.append({
                    "pid": info["pid"],
                    "name": info["name"] or "",
                    "user": info["username"] or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    else:
        try:
            proc = subprocess.run(
                ["ps", "-eo", "pid,comm,user", "--no-headers"],
                capture_output=True, text=True, timeout=10,
            )
            for line in proc.stdout.splitlines():
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    processes.append({
                        "pid": int(parts[0]),
                        "name": parts[1],
                        "user": parts[2] if len(parts) >= 3 else "",
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    payload["processes"] = processes[:100]
    payload["hostname"] = os.environ.get("HOSTNAME", "unknown")
    return payload


def observe_sessions_fallback() -> dict[str, Any]:
    """Fallback: who is logged in."""
    payload: dict[str, Any] = {"source": "mask_adapter_fallback"}
    sessions: list[dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["who"], capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 1:
                sessions.append({
                    "user": parts[0],
                    "terminal": parts[1] if len(parts) >= 2 else "",
                    "login_time": " ".join(parts[2:4]) if len(parts) >= 4 else "",
                })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    # Also try psutil for users
    if psutil:
        for user in psutil.users():
            sessions.append({
                "user": user.name,
                "terminal": user.terminal or "",
                "login_time_ms": int(float(user.started) * 1000) if user.started else 0,
            })
    payload["sessions"] = sessions
    payload["hostname"] = os.environ.get("HOSTNAME", "unknown")
    return payload


# ---------------------------------------------------------------------------
# Envelope builders
# ---------------------------------------------------------------------------

def make_sysinfo_envelope(payload: dict[str, Any]) -> CrossAppEnvelope:
    return CrossAppEnvelope(
        timestamp_ms=now_ms(),
        asset_id=MASK_ASSET_ID,
        source="MASK",
        source_version="0.3.0",
        event_type="sysinfo_observation",
        severity="info",
        category="system",
        description=f"System metrics for {payload.get('hostname', 'mask-host')}",
        payload=payload,
        tenant_id="wolfpak-tenant-01",
    )


def make_network_envelope(payload: dict[str, Any]) -> CrossAppEnvelope:
    nconn = len(payload.get("connections", []))
    severity = "high" if nconn > 50 else ("medium" if nconn > 20 else "low")
    return CrossAppEnvelope(
        timestamp_ms=now_ms(),
        asset_id=MASK_ASSET_ID,
        source="MASK",
        source_version="0.3.0",
        event_type="network_connection_observation",
        severity=severity,
        category="network",
        description=f"{nconn} active TCP connections on {payload.get('hostname', 'mask-host')}",
        payload=payload,
        tenant_id="wolfpak-tenant-01",
    )


def make_process_envelope(payload: dict[str, Any]) -> CrossAppEnvelope:
    return CrossAppEnvelope(
        timestamp_ms=now_ms(),
        asset_id=MASK_ASSET_ID,
        source="MASK",
        source_version="0.3.0",
        event_type="process_observation",
        severity="info",
        category="process",
        description=f"Process list for {payload.get('hostname', 'mask-host')} ({len(payload.get('processes', []))} processes)",
        payload=payload,
        tenant_id="wolfpak-tenant-01",
    )


def make_session_envelope(payload: dict[str, Any]) -> CrossAppEnvelope:
    nusers = len(payload.get("sessions", []))
    severity = "medium" if nusers > 3 else "low"
    return CrossAppEnvelope(
        timestamp_ms=now_ms(),
        asset_id=MASK_ASSET_ID,
        source="MASK",
        source_version="0.3.0",
        event_type="user_sessions",
        severity=severity,
        category="auth",
        description=f"{nusers} users logged in on {payload.get('hostname', 'mask-host')}",
        payload=payload,
        tenant_id="wolfpak-tenant-01",
    )


# ---------------------------------------------------------------------------
# Main observation + push
# ---------------------------------------------------------------------------

def observe_and_push(url: str) -> int:
    """Run one full observation cycle and push all events. Returns count pushed."""
    pushed = 0

    # 1. Sysinfo
    sysinfo_payload = observe_sysinfo_mask() or observe_sysinfo_fallback()
    env = make_sysinfo_envelope(sysinfo_payload)
    if post_event(url, env):
        pushed += 1

    # 2. Network connections
    network_payload = observe_network_mask() or observe_network_fallback()
    env = make_network_envelope(network_payload)
    if post_event(url, env):
        pushed += 1

    # 3. Processes
    process_payload = observe_processes_mask() or observe_processes_fallback()
    env = make_process_envelope(process_payload)
    if post_event(url, env):
        pushed += 1

    # 4. Sessions
    session_payload = observe_sessions_fallback()
    env = make_session_envelope(session_payload)
    if post_event(url, env):
        pushed += 1

    return pushed


def main() -> None:
    global MASK_ASSET_ID
    ap = argparse.ArgumentParser(description="Export MASK host observations to Wolf-Pak Event Fabric")
    ap.add_argument("--url", default="http://127.0.0.1:8080/api/event-fabric/intake",
                    help="NG intake endpoint (default: %(default)s)")
    ap.add_argument("--interval", type=int, default=30,
                    help="Poll interval in seconds (default: %(default)s)")
    ap.add_argument("--once", action="store_true",
                    help="Run one cycle and exit")
    ap.add_argument("--asset-id", default=MASK_ASSET_ID,
                    help="Asset ID to use (default: %(default)s)")
    args = ap.parse_args()
    MASK_ASSET_ID = args.asset_id

    logger.info("MASK adapter starting — url=%s interval=%ds asset=%s",
                args.url, args.interval, args.asset_id)

    if args.once:
        count = observe_and_push(args.url)
        logger.info("Done: %d events pushed", count)
        sys.exit(0 if count > 0 else 1)

    while True:
        try:
            count = observe_and_push(args.url)
            logger.info("Cycle complete: %d events pushed", count)
        except Exception as exc:
            logger.error("Cycle failed: %s", exc)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
