# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
#!/usr/bin/env python3
"""ng-fleet — Wolfpak fleet management CLI.

Manage and monitor all deployed field agents from the command line.

Usage:
    ng-fleet list                 List all agents
    ng-fleet inspect <agent-id>   Detailed agent view
    ng-fleet watch [--interval N] Auto-refresh list
    ng-fleet clients              Show connected wolfpak admin clients

Options:
    --base URL      Base station URL (default: http://127.0.0.1:8080)
    --interval N    Refresh interval in seconds for watch mode (default: 5)
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from network_guardian.wolfpak.client import (
    WolfpakClient,
    R, B, DIM, RED, GRN, YLW, BLU, MAG, CYN,
    BRED, BGRN, BYEL, BBLU, BMAG, BCYN,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_STATUS_COLOR = {
    "online":  BGRN,
    "stale":   BYEL,
    "offline": DIM,
}

_STATUS_ICON = {
    "online":  "●",
    "stale":   "◐",
    "offline": "○",
}


def _threat_color(score: float | None) -> str:
    if score is None:
        return DIM
    if score >= 7:
        return BRED
    if score >= 4:
        return BYEL
    return BGRN


def _covert_chip(a: dict) -> str:
    proxy = a.get("covert_proxy", "none") or "none"
    if "9050" in proxy or "9150" in proxy or "tor" in proxy.lower():
        return f"{BGRN}🔒 Tor{R}"
    if proxy != "none" and proxy:
        return f"{BBLU}🔒 Proxy{R}"
    return f"{DIM}🔓 Direct{R}"


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_list(client: WolfpakClient) -> None:
    """Print all fleet agents as a table."""
    data  = client.get("/api/fleet/list")
    agents = data if isinstance(data, list) else data.get("agents", [])

    total   = len(agents)
    online  = sum(1 for a in agents if a.get("status") == "online")
    covert  = sum(1 for a in agents if (a.get("covert_proxy") or "none") != "none")
    threats = sum(1 for a in agents if (a.get("react_threat_score") or 0) >= 4)
    sents   = sum(1 for a in agents if a.get("is_sentinel"))

    client.banner("Fleet Command", f"{total} agents  ·  {online} online  ·  {covert} covert  ·  {threats} threats")

    # KPI row
    print(f"\n  {B}Total{R} {total}    {BGRN}Online{R} {online}    "
          f"{BMAG}🔒 Covert{R} {covert}    {BRED}Threats{R} {threats}    "
          f"{BCYN}Sentinels{R} {sents}\n")

    if not agents:
        print(f"  {DIM}No agents registered yet.{R}\n")
        return

    # Header
    W = [22, 8, 16, 5, 6, 8, 10, 9]
    hdr = ["AGENT ID", "STATUS", "IP", "WIFI", "HOSTS", "REPORTS", "SEEN", "COVERT"]
    print(f"  {DIM}" + "  ".join(f"{h:<{W[i]}}" for i, h in enumerate(hdr)) + R)
    print(f"  {DIM}{'─' * 96}{R}")

    for a in sorted(agents, key=lambda x: x.get("last_seen", 0), reverse=True):
        st  = a.get("status", "offline")
        sc  = _STATUS_COLOR.get(st, DIM)
        ico = _STATUS_ICON.get(st, "○")
        ago = client.ago(a.get("last_seen"))
        covert_s = _covert_chip(a)
        sentinel_s = f" {BCYN}[S]{R}" if a.get("is_sentinel") else ""

        agent_id = (a.get("agent_id") or "")[:22]
        print(
            f"  {B}{agent_id:<22}{R}{sentinel_s}"
            f"  {sc}{ico} {st:<6}{R}"
            f"  {BLU}{(a.get('ip') or ''):<16}{R}"
            f"  {a.get('wifi_count', 0):<5}"
            f"  {a.get('host_count', 0):<6}"
            f"  {a.get('report_count', 0):<8}"
            f"  {DIM}{ago:<10}{R}"
            f"  {covert_s}"
        )
    print()


def cmd_inspect(client: WolfpakClient, agent_id: str) -> None:
    """Print detailed info for a single agent."""
    data   = client.get("/api/fleet/list")
    agents = data if isinstance(data, list) else data.get("agents", [])

    # Find agent (partial match OK)
    match = [a for a in agents if agent_id.lower() in (a.get("agent_id") or "").lower()]
    if not match:
        print(f"  {BRED}✗ Agent '{agent_id}' not found{R}")
        sys.exit(1)
    a = match[0]

    st  = a.get("status", "offline")
    sc  = _STATUS_COLOR.get(st, DIM)
    ico = _STATUS_ICON.get(st, "○")

    client.banner(
        f"Agent: {a.get('agent_id')}",
        f"{sc}{ico} {st.upper()}{R}  ·  {a.get('ip', 'unknown')}",
    )

    def row(label: str, val: str, color: str = "") -> None:
        print(f"  {DIM}{label:<22}{R}{color}{val}{R}")

    print()
    row("Agent ID",       a.get("agent_id", ""))
    row("Hostname",       a.get("hostname", "") or a.get("agent_name", ""))
    row("IP Address",     a.get("ip", "unknown"), BLU)
    row("Subnet",         a.get("subnet", ""))
    row("Status",         f"{sc}{a.get('status', '?').upper()}{R}")
    row("Last Seen",      client.ago(a.get("last_seen")))
    row("First Seen",     client.ago(a.get("first_seen")))
    row("Reports Sent",   str(a.get("report_count", 0)))
    row("Sentinel",       "Yes" if a.get("is_sentinel") else "No",
        BCYN if a.get("is_sentinel") else DIM)

    print(f"\n  {B}── Network ──────────────────────────────────────────{R}")
    row("WiFi Networks",  str(a.get("wifi_count", 0)))
    row("Hosts Found",    str(a.get("host_count", 0)))

    print(f"\n  {B}── Covert Channel ───────────────────────────────────{R}")
    proxy  = a.get("covert_proxy", "none") or "none"
    jitter = a.get("covert_jitter", "off") or "off"
    decoys = a.get("covert_decoys", 0) or 0
    ua     = a.get("covert_ua", False)
    pad    = a.get("covert_padding", False)

    if proxy != "none":
        row("Proxy",     proxy, BGRN)
    else:
        row("Proxy",     f"{BRED}none — base IP exposed{R}")
    row("Jitter",        jitter)
    row("Decoys",        str(decoys))
    row("UA Rotation",   "Yes" if ua else "No")
    row("Body Padding",  "Yes" if pad else "No")

    print(f"\n  {B}── ReAct Threat Analysis ────────────────────────────{R}")
    score = a.get("react_threat_score")
    tc    = _threat_color(score)
    row("Threat Score",  f"{tc}{score if score is not None else 'N/A'}/10{R}")
    row("Risk Level",    a.get("react_risk_level", "unknown").upper())
    row("Issues Found",  str(a.get("react_issues_count", 0)))

    # Recent findings
    findings = a.get("recent_findings") or []
    if findings:
        print(f"\n  {B}── Recent Findings ──────────────────────────────────{R}")
        for f in findings[:5]:
            sev = (f.get("severity") or "info").upper()
            sev_c = BRED if sev == "CRITICAL" else (BYEL if sev == "HIGH" else DIM)
            print(f"  {sev_c}[{sev}]{R}  {f.get('title', f.get('description', ''))}")

    # Sentinel intelligence
    if a.get("is_sentinel"):
        si = a.get("sentinel_intel") or {}
        print(f"\n  {B}── Sentinel Intelligence ────────────────────────────{R}")
        row("WiFi Changes",   str(si.get("wifi_changes", 0)))
        row("Rogue APs",      str(si.get("rogue_aps", 0)),
            BRED if si.get("rogue_aps") else "")
        row("New Flows",      str(si.get("new_flows", 0)))
        row("Cycle Count",    str(si.get("cycles", 0)))
    print()


def cmd_watch(client: WolfpakClient, interval: int) -> None:
    """Auto-refresh the agent list every N seconds."""
    try:
        while True:
            if sys.stdout.isatty():
                # Clear screen without spawning a shell.
                print("\033[2J\033[H", end="")
            cmd_list(client)
            print(f"  {DIM}Refreshing every {interval}s — Ctrl+C to stop{R}\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n  {DIM}Stopped.{R}\n")


def cmd_clients(client: WolfpakClient) -> None:
    """Show connected wolfpak admin clients as seen by the base."""
    data    = client.get("/api/wolfpak/clients")
    clients = data if isinstance(data, list) else data.get("clients", [])

    client.banner("Wolfpak Admin Clients", f"{len(clients)} registered device(s)")

    if not clients:
        print(f"\n  {DIM}No wolfpak clients have connected yet.{R}\n")
        return

    W = [16, 14, 16, 16, 8, 10]
    hdr = ["TAG", "HOST", "TOOL", "USER", "REQS", "LAST SEEN"]
    print(f"\n  {DIM}" + "  ".join(f"{h:<{W[i]}}" for i, h in enumerate(hdr)) + R)
    print(f"  {DIM}{'─' * 86}{R}")

    for c in clients:
        ago_s  = client.ago(c.get("last_seen_ts") or c.get("last_seen"))
        tag_s  = (c.get("tag") or "")[:14]
        tool_c = BCYN if c.get("tool", "").startswith("ng-") else DIM
        print(
            f"  {BMAG}{tag_s:<16}{R}"
            f"  {BLU}{(c.get('host') or '')[:14]:<14}{R}"
            f"  {tool_c}{(c.get('tool') or ''):<16}{R}"
            f"  {B}{(c.get('username') or ''):<16}{R}"
            f"  {c.get('request_count', 0):<8}"
            f"  {DIM}{ago_s:<10}{R}"
        )
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ng-fleet",
        description="Wolfpak fleet management CLI",
    )
    parser.add_argument("command", nargs="?", default="list",
                        choices=["list", "inspect", "watch", "clients"],
                        help="Command to run (default: list)")
    parser.add_argument("agent", nargs="?", help="Agent ID for inspect command")
    parser.add_argument("--base", default=os.environ.get("NG_BASE", "http://127.0.0.1:8080"),
                        help="Base station URL")
    parser.add_argument("--interval", type=int, default=5,
                        help="Refresh interval for watch mode (seconds)")
    args = parser.parse_args()

    client = WolfpakClient(args.base, tool="ng-fleet")
    client.ensure_auth()

    if args.command == "list":
        cmd_list(client)
    elif args.command == "inspect":
        if not args.agent:
            print(f"  {BRED}✗ Usage: ng-fleet inspect <agent-id>{R}")
            sys.exit(1)
        cmd_inspect(client, args.agent)
    elif args.command == "watch":
        cmd_watch(client, args.interval)
    elif args.command == "clients":
        cmd_clients(client)


if __name__ == "__main__":
    main()
