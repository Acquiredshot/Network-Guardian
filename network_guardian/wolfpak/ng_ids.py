#!/usr/bin/env python3
"""ng-ids — Wolfpak IDS/IPS management CLI.

View intrusion detection alerts, manage the IPS blocklist, and control
the prevention engine from the command line.

Usage:
    ng-ids status               Combined IDS + IPS status
    ng-ids alerts [--limit N]   Recent IDS alert feed
    ng-ids rules                List all IDS signature rules
    ng-ids block <ip>           Block an IP via IPS
    ng-ids unblock <ip>         Unblock an IP
    ng-ids blocklist            Show current IPS blocklist

Options:
    --base URL      Base station URL (default: http://127.0.0.1:8080)
    --limit N       Number of alerts to show (default: 20)
"""

from __future__ import annotations

import argparse
import os
import sys

from network_guardian.wolfpak.client import (
    WolfpakClient,
    R, B, DIM, RED, GRN, YLW, BLU, MAG, CYN,
    BRED, BGRN, BYEL, BBLU, BMAG, BCYN,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLOR = {
    "critical": BRED,
    "high":     f"\033[1;31m" if sys.stdout.isatty() else "",  # bold red-orange
    "medium":   BYEL,
    "low":      BGRN,
    "info":     DIM,
}

_SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}


def _sev_c(sev: str) -> str:
    return _SEV_COLOR.get(sev.lower(), DIM)


def _sev_i(sev: str) -> str:
    return _SEV_ICON.get(sev.lower(), "⚪")


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_status(client: WolfpakClient) -> None:
    """Show combined IDS + IPS status."""
    ids = client.get("/api/ids/stats")
    ips = client.get("/api/ips/stats")

    total  = ids.get("total_alerts", 0)
    sev    = ids.get("by_severity", {})
    crit   = sev.get("critical", 0)
    high   = sev.get("high", 0)

    ips_bl = ips.get("blocked_ips", 0)
    ips_rl = ips.get("rate_limited_ips", 0)
    ips_q  = ips.get("quarantined_ips", 0)

    threat = (BRED + "CRITICAL" if crit else
              BYEL + "HIGH"     if high else
              BYEL + "ELEVATED" if total else
              BGRN + "CLEAN")

    client.banner("IDS / IPS Status", f"Threat level: {threat}{R}")

    print()
    print(f"  {B}── Intrusion Detection ─────────────────────────────{R}")
    print(f"  Rules Loaded   {ids.get('rules_loaded', 0)}")
    print(f"  Total Alerts   {BRED if total else DIM}{total}{R}")
    print(f"  {_SEV_ICON['critical']} Critical   {BRED if crit else DIM}{crit}{R}")
    print(f"  {_SEV_ICON['high']}    High       {BYEL if high else DIM}{high}{R}")
    print(f"  {_SEV_ICON['medium']}   Medium     {sev.get('medium', 0)}")
    print(f"  {_SEV_ICON['low']}    Low        {sev.get('low', 0)}")

    print(f"\n  {B}── Intrusion Prevention ────────────────────────────{R}")
    ips_run = ips.get("running", True)
    print(f"  Engine         {BGRN + 'ACTIVE' if ips_run else BRED + 'STOPPED'}{R}")
    print(f"  Blocked IPs    {BRED if ips_bl else DIM}{ips_bl}{R}")
    print(f"  Rate Limited   {BYEL if ips_rl else DIM}{ips_rl}{R}")
    print(f"  Quarantined    {BMAG if ips_q else DIM}{ips_q}{R}")
    print(f"  Total Events   {ips.get('total_events', 0)}")
    print()


def cmd_alerts(client: WolfpakClient, limit: int) -> None:
    """Print recent IDS alert feed."""
    alerts = client.get("/api/ids/alerts")
    if isinstance(alerts, dict):
        alerts = alerts.get("alerts", [])

    client.banner("IDS Alert Feed", f"{len(alerts)} total alerts")

    if not alerts:
        print(f"\n  {BGRN}✓ No alerts — system clean{R}\n")
        return

    shown = list(reversed(alerts))[:limit]
    print()
    for a in shown:
        sev  = (a.get("severity") or "info").lower()
        sc   = _sev_c(sev)
        icon = _sev_i(sev)
        ts   = (a.get("timestamp") or "")[:19].replace("T", " ")
        rule = a.get("rule_name") or a.get("rule", "")
        src  = a.get("source_ip") or a.get("src_ip") or ""
        desc = a.get("description") or ""

        print(f"  {icon}  {sc}{sev.upper():<8}{R}  {DIM}{ts}{R}  "
              f"{B}{rule:<30}{R}  {BLU}{src:<16}{R}")
        if desc:
            print(f"  {DIM}   └─ {desc[:80]}{R}")
    print()


def cmd_rules(client: WolfpakClient) -> None:
    """List all loaded IDS signature rules."""
    rules = client.get("/api/ids/rules")
    if isinstance(rules, dict):
        rules = rules.get("rules", [])

    client.banner("IDS Signature Rules", f"{len(rules)} rules loaded")

    if not rules:
        print(f"\n  {DIM}No rules loaded.{R}\n")
        return

    W = [6, 8, 32, 18, 12]
    hdr = ["SID", "SEV", "NAME", "CATEGORY", "METHOD"]
    print(f"\n  {DIM}" + "  ".join(f"{h:<{W[i]}}" for i, h in enumerate(hdr)) + R)
    print(f"  {DIM}{'─' * 84}{R}")

    for r in rules:
        sev  = (r.get("severity") or "info").lower()
        sc   = _sev_c(sev)
        icon = _sev_i(sev)
        print(
            f"  {DIM}{str(r.get('sid', '')):<6}{R}"
            f"  {sc}{icon} {sev:<6}{R}"
            f"  {B}{(r.get('name') or '')[:32]:<32}{R}"
            f"  {DIM}{(r.get('category') or ''):<18}{R}"
            f"  {CYN}{(r.get('method') or 'signature'):<12}{R}"
        )
    print()


def cmd_block(client: WolfpakClient, ip: str) -> None:
    """Block an IP via IPS."""
    result = client.post("/api/control/ips/block", {"ip": ip, "reason": "wolfpak-admin"})
    if result.get("ok") or result.get("blocked") or result.get("status") == "ok":
        print(f"\n  {BGRN}✓ Blocked {ip}{R}\n")
    else:
        msg = result.get("error", result.get("message", "unknown response"))
        print(f"\n  {BYEL}⚠ {msg}{R}\n")


def cmd_unblock(client: WolfpakClient, ip: str) -> None:
    """Unblock an IP via IPS."""
    result = client.post("/api/control/ips/unblock", {"ip": ip})
    if result.get("ok") or result.get("unblocked") or result.get("status") == "ok":
        print(f"\n  {BGRN}✓ Unblocked {ip}{R}\n")
    else:
        msg = result.get("error", result.get("message", "unknown response"))
        print(f"\n  {BYEL}⚠ {msg}{R}\n")


def cmd_blocklist(client: WolfpakClient) -> None:
    """Show IPS blocklist."""
    blocked = client.get("/api/ips/blocklist")
    if isinstance(blocked, dict):
        blocked = blocked.get("blocked", [])

    client.banner("IPS Blocklist", f"{len(blocked)} blocked IP(s)")

    if not blocked:
        print(f"\n  {BGRN}✓ No blocked IPs{R}\n")
        return

    print()
    for b in blocked:
        ip     = b.get("ip", str(b))
        hits   = b.get("hit_count", 0)
        reason = b.get("reason", "")
        expire = b.get("expires_at")
        exp_s  = f"  {DIM}expires {expire}{R}" if expire else ""
        print(f"  {BRED}✗{R}  {BLU}{ip:<18}{R}  {DIM}{hits} hits{R}  "
              f"{BYEL}{reason}{R}{exp_s}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ng-ids",
        description="Wolfpak IDS/IPS management CLI",
    )
    parser.add_argument("command", nargs="?", default="status",
                        choices=["status", "alerts", "rules", "block", "unblock", "blocklist"],
                        help="Command to run (default: status)")
    parser.add_argument("ip", nargs="?", help="IP address for block/unblock commands")
    parser.add_argument("--base", default=os.environ.get("NG_BASE", "http://127.0.0.1:8080"),
                        help="Base station URL")
    parser.add_argument("--limit", type=int, default=20,
                        help="Alert count limit (default: 20)")
    args = parser.parse_args()

    client = WolfpakClient(args.base, tool="ng-ids")
    client.ensure_auth()

    if args.command == "status":
        cmd_status(client)
    elif args.command == "alerts":
        cmd_alerts(client, args.limit)
    elif args.command == "rules":
        cmd_rules(client)
    elif args.command == "block":
        if not args.ip:
            print(f"  {BRED}✗ Usage: ng-ids block <ip>{R}")
            sys.exit(1)
        cmd_block(client, args.ip)
    elif args.command == "unblock":
        if not args.ip:
            print(f"  {BRED}✗ Usage: ng-ids unblock <ip>{R}")
            sys.exit(1)
        cmd_unblock(client, args.ip)
    elif args.command == "blocklist":
        cmd_blocklist(client)


if __name__ == "__main__":
    main()
