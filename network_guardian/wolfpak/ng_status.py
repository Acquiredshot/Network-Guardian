#!/usr/bin/env python3
"""ng-status — Wolfpak system status overview CLI.

Quick health snapshot of the entire Network Guardian base station.
Shows engine status, IDS/IPS counts, fleet summary, connected admin
clients, and current threat level in a single view.

Usage:
    ng-status                   Single health snapshot
    ng-status --watch           Auto-refresh every 5 seconds

Options:
    --base URL      Base station URL (default: http://127.0.0.1:8080)
    --interval N    Watch mode refresh interval (default: 5)
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

def _threat_label(ids: dict) -> tuple[str, str]:
    sev  = ids.get("by_severity", {})
    alts = ids.get("total_alerts", 0)
    if sev.get("critical"):
        return "CRITICAL", BRED
    if sev.get("high"):
        return "HIGH", BYEL
    if alts:
        return "ELEVATED", BYEL
    return "CLEAN", BGRN


def _section(title: str) -> None:
    print(f"\n  {B}── {title} {'─' * max(0, 50 - len(title))}{R}")


# ─────────────────────────────────────────────────────────────────────────────
# Main snapshot
# ─────────────────────────────────────────────────────────────────────────────

def snapshot(client: WolfpakClient) -> None:
    # Fetch all data (best-effort; failures show '?' not crash)
    def safe(path: str) -> dict | list:
        try:
            return client.get(path)
        except SystemExit:
            return {}

    status  = safe("/api/status")
    ids     = safe("/api/ids/stats")
    ips     = safe("/api/ips/stats")
    fleet   = safe("/api/fleet/list")
    clients = safe("/api/wolfpak/clients")
    hosts   = safe("/api/hosts")
    events  = safe("/api/events")
    wifi    = safe("/api/wifi/networks")

    agents    = fleet if isinstance(fleet, list) else fleet.get("agents", [])
    wp_clis   = clients if isinstance(clients, list) else clients.get("clients", [])
    host_map  = hosts if isinstance(hosts, dict) else {}
    ev_list   = events if isinstance(events, list) else []
    wifi_nets = wifi if isinstance(wifi, list) else []

    # Summary numbers
    threat_label, threat_color = _threat_label(ids if isinstance(ids, dict) else {})
    total_alerts = (ids.get("total_alerts", 0) if isinstance(ids, dict) else 0)
    ips_blocked  = (ips.get("blocked_ips", 0)  if isinstance(ips, dict) else 0)

    ag_online  = sum(1 for a in agents if a.get("status") == "online")
    ag_covert  = sum(1 for a in agents if (a.get("covert_proxy") or "none") != "none")
    ag_threats = sum(1 for a in agents if (a.get("react_threat_score") or 0) >= 4)

    # Active wolfpak clients (seen in last 5 minutes)
    now = time.time()
    wp_active = sum(1 for c in wp_clis if now - (c.get("last_seen_ts") or 0) < 300)

    client.banner(
        "Network Guardian — System Status",
        f"Threat: {threat_color}{threat_label}{R}  ·  "
        f"{len(agents)} agents  ·  {len(wp_clis)} wolfpak devices",
    )

    # ── Engine ────────────────────────────────────────────────────────────
    _section("Engine")
    eng = status if isinstance(status, dict) else {}
    running = eng.get("running", True)
    print(f"  Engine         {BGRN + 'ACTIVE' if running else BRED + 'STOPPED'}{R}")
    print(f"  Hosts Tracked  {len(host_map)}")
    print(f"  Events         {len(ev_list)}")
    print(f"  WiFi Networks  {len(wifi_nets)}")

    # ── Threat ────────────────────────────────────────────────────────────
    _section("Threat Intelligence")
    sev = (ids.get("by_severity", {}) if isinstance(ids, dict) else {})
    print(f"  Level          {threat_color}{threat_label}{R}")
    print(f"  IDS Alerts     {BRED if total_alerts else DIM}{total_alerts}{R}"
          f"  {DIM}(crit:{sev.get('critical',0)}  high:{sev.get('high',0)}"
          f"  med:{sev.get('medium',0)}){R}")
    print(f"  IPS Blocked    {BRED if ips_blocked else DIM}{ips_blocked}{R}")
    rules = (ids.get("rules_loaded", 0) if isinstance(ids, dict) else 0)
    print(f"  IDS Rules      {rules}")

    # ── Fleet ─────────────────────────────────────────────────────────────
    _section("Fleet Agents")
    print(f"  Total          {len(agents)}")
    print(f"  Online         {BGRN if ag_online else DIM}{ag_online}{R}")
    print(f"  Covert         {BMAG}{ag_covert}{R}")
    print(f"  Threats        {BRED if ag_threats else DIM}{ag_threats}{R}")

    # ── Wolfpak Admins ────────────────────────────────────────────────────
    _section("Wolfpak Admin Clients")
    print(f"  Registered     {len(wp_clis)}")
    print(f"  Active (5m)    {BGRN if wp_active else DIM}{wp_active}{R}")

    if wp_clis:
        print()
        for c in wp_clis[:5]:
            ago_s = client.ago(c.get("last_seen_ts") or c.get("last_seen"))
            is_me = (c.get("tag") or "").startswith(client.tag_id[:8])
            me_s  = f" {BCYN}(you){R}" if is_me else ""
            print(f"    {BMAG}{(c.get('tag') or '')[:8]}{R}  "
                  f"{BLU}{(c.get('host') or '')[:16]:<16}{R}  "
                  f"{CYN}{c.get('tool', ''):<12}{R}  "
                  f"{DIM}{ago_s}{R}{me_s}")

    # ── My Device ─────────────────────────────────────────────────────────
    _section("This Device")
    print(f"  Tag            {BMAG}{client.tag_id[:8]}{DIM}...{R}  "
          f"{DIM}({client.hostname}){R}")
    print(f"  Username       {B}{client.username}{R}")
    print(f"  Base           {BLU}{client.base}{R}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ng-status",
        description="Wolfpak system status overview",
    )
    parser.add_argument("--base", default=os.environ.get("NG_BASE", "http://127.0.0.1:8080"),
                        help="Base station URL")
    parser.add_argument("--watch", action="store_true",
                        help="Auto-refresh mode")
    parser.add_argument("--interval", type=int, default=5,
                        help="Refresh interval in seconds (default: 5)")
    args = parser.parse_args()

    client = WolfpakClient(args.base, tool="ng-status")
    client.ensure_auth()

    if args.watch:
        try:
            while True:
                if sys.stdout.isatty():
                    os.system("clear")
                snapshot(client)
                print(f"  {DIM}Refreshing every {args.interval}s — Ctrl+C to stop{R}\n")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n  {DIM}Stopped.{R}\n")
    else:
        snapshot(client)


if __name__ == "__main__":
    main()
