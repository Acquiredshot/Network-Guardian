"""
network_guardian/cli/hud.py  |  TAC-HUD — live cyberpunk radar monitor
════════════════════════════════════════════════════════════════════
A full-terminal, self-refreshing HUD for Network Guardian: a radar
sweep of LAN neighbors, a threat-score gauge, system vitals, fleet
status and a scrolling threat log. Reads the same on-disk state the
web dashboard and Jarvis read (fleet.json) plus live OS metrics —
no server connection required.

Run with:  ng-hud   (or)   python -m network_guardian.cli.hud
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from network_guardian.jarvis.telemetry_aggregator import PATHS, TelemetryAggregator

# ══════════════════════════════════════════════════════════════════
# PALETTE — mirrors the TAC-HUD design concept
# ══════════════════════════════════════════════════════════════════

CYAN     = "#3fe7ff"
CYAN_HOT = "#bffaff"
CYAN_DIM = "#1c6b7a"
MINT     = "#35ffaa"
AMBER    = "#ffb020"
RED      = "#ff3b57"
DIM      = "#6e8aa0"
FAINT    = "#3d5566"
BRIGHT   = "#e8f6ff"
GRID     = "#1c2e3d"

SEV_COLOR = {"critical": RED, "high": RED, "medium": AMBER, "low": DIM, "info": DIM}
LEVEL_COLOR = {"critical": RED, "high": AMBER, "elevated": AMBER, "medium": AMBER, "low": MINT, "nominal": MINT}


def _blend(hex_a: str, hex_b: str, t: float) -> str:
    t = max(0.0, min(1.0, t))
    a = tuple(int(hex_a[i:i + 2], 16) for i in (1, 3, 5))
    b = tuple(int(hex_b[i:i + 2], 16) for i in (1, 3, 5))
    mixed = tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))
    return f"#{mixed[0]:02x}{mixed[1]:02x}{mixed[2]:02x}"


# ══════════════════════════════════════════════════════════════════
# DATA — read the exact files the dashboard/Jarvis already maintain
# ══════════════════════════════════════════════════════════════════

def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def _self_agent(fleet_raw: dict | None) -> tuple[str | None, dict]:
    agents = (fleet_raw or {}).get("agents", {}) if isinstance(fleet_raw, dict) else {}
    if not agents:
        return None, {}
    hostname = socket.gethostname().lower()
    for agent_id, agent in agents.items():
        if str((agent.get("identity") or {}).get("hostname", "")).lower() == hostname:
            return agent_id, agent
    return next(iter(agents.items()))


def _fleet_counts(fleet_raw: dict | None) -> dict[str, int]:
    agents = (fleet_raw or {}).get("agents", {}) if isinstance(fleet_raw, dict) else {}
    online = sum(1 for a in agents.values() if str(a.get("status", "")).lower() == "online")
    return {"total": len(agents), "online": online, "offline": len(agents) - online}


def _latest_report(agent: dict) -> dict | None:
    reports = agent.get("threat_reports") or []
    if not reports:
        return None
    return max(reports, key=lambda r: r.get("generated_at", ""))


def _log_entries(agent: dict, limit: int = 8) -> list[dict]:
    entries = list(agent.get("threat_history") or [])
    latest = _latest_report(agent)
    if latest:
        seen = {(e.get("timestamp"), e.get("title")) for e in entries}
        for t in latest.get("threats", []):
            key = (t.get("timestamp"), t.get("title"))
            if key not in seen:
                entries.append(t)
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return entries[:limit]


def _ip_polar(ip: str) -> tuple[float, float]:
    """Deterministic angle/radius so a given host stays put between refreshes."""
    h = hashlib.sha1(ip.encode()).hexdigest()
    angle = float(int(h[:4], 16) % 360)
    frac = 0.25 + (int(h[4:8], 16) % 700) / 1000.0
    return angle, min(frac, 0.95)


# ══════════════════════════════════════════════════════════════════
# RADAR — hand-drawn ASCII scope with a rotating sweep
# ══════════════════════════════════════════════════════════════════

_COLS, _ROWS = 45, 21
_CX, _CY = _COLS // 2, _ROWS // 2
_RADIUS = 20.0
_ASPECT = 2.1
_BEAM_HALF = 3.5
_TRAIL_HALF = 24.0


def render_radar(agent: dict, sweep_deg: float) -> Text:
    last_report = agent.get("last_report") or {}
    hosts = [h for h in (last_report.get("discovered_hosts") or []) if h.get("alive")][:28]
    local_ip = last_report.get("local_ip", "")
    gateway_ip = last_report.get("gateway") or local_ip or "—"

    risky: dict[str, str] = {}
    for entry in _log_entries(agent, limit=20):
        ip = entry.get("source_ip")
        sev = str(entry.get("severity", "")).lower()
        if ip and sev in ("critical", "high", "medium"):
            risky[ip] = sev

    grid: list[list[tuple[str, str | None]]] = [[(" ", None)] * _COLS for _ in range(_ROWS)]

    for row in range(_ROWS):
        for col in range(_COLS):
            dx = col - _CX
            dy = (row - _CY) * _ASPECT
            dist = math.hypot(dx, dy)
            if dist > _RADIUS:
                continue
            angle = (math.degrees(math.atan2(dy, dx)) + 360) % 360
            diff = abs(angle - sweep_deg)
            diff = min(diff, 360 - diff)

            is_ring = any(abs(dist - _RADIUS * f) < 0.55 for f in (1 / 3, 2 / 3, 1.0))
            is_axis = row == _CY or col == _CX
            char = "·" if (is_ring or is_axis) else " "
            style = GRID

            if diff < _BEAM_HALF:
                char = "•" if char == " " else char
                style = CYAN_HOT
            elif diff < _TRAIL_HALF:
                fade = 1 - diff / _TRAIL_HALF
                char = "·" if char == " " else char
                style = _blend(GRID, CYAN, fade)

            grid[row][col] = (char, style)

    for host in hosts:
        ip = host.get("ip", "")
        if not ip or ip == gateway_ip:
            continue
        angle, frac = _ip_polar(ip)
        rad = math.radians(angle)
        col = _CX + round(math.cos(rad) * _RADIUS * frac)
        row = _CY + round(math.sin(rad) * _RADIUS * frac / _ASPECT)
        if 0 <= row < _ROWS and 0 <= col < _COLS:
            color = risky.get(ip, MINT)
            grid[row][col] = ("●", color)

    grid[_CY][_CX] = ("◈", CYAN)

    text = Text(no_wrap=True, justify="center")
    for row in grid:
        for char, style in row:
            text.append(char, style=style)
        text.append("\n")
    return text


def render_radar_panel(agent: dict, sweep_deg: float) -> Panel:
    last_report = agent.get("last_report") or {}
    gateway = last_report.get("gateway") or last_report.get("local_ip") or "—"
    arp_n = (_latest_report(agent) or {}).get("observations", {}).get("arp_entries", "—")

    body = Group(
        Align.center(render_radar(agent, sweep_deg)),
        Text(f"GW {gateway} — {arp_n} ARP ENTRIES OBSERVED", style=FAINT, justify="center"),
        Text.assemble(
            ("  ● ", MINT), ("NOMINAL   ", DIM),
            ("● ", AMBER), ("ELEVATED   ", DIM),
            ("● ", RED), ("CRITICAL", DIM),
            justify="center",
        ),
    )
    return Panel(
        Align(body, align="center", vertical="middle"),
        title="[dim]PASSIVE SCAN — ARP NEIGHBOR SWEEP[/]",
        title_align="left",
        border_style=GRID,
        box=box.SQUARE,
    )


# ══════════════════════════════════════════════════════════════════
# GAUGE / VITALS / FLEET / LOG PANELS
# ══════════════════════════════════════════════════════════════════

def render_gauge_panel(latest: dict | None) -> Panel:
    score = float(latest.get("threat_score", 0)) if latest else 0.0
    level = str(latest.get("risk_level", "nominal")).lower() if latest else "nominal"
    color = LEVEL_COLOR.get(level, MINT)

    big = Text(f"{score:.0f}", style=f"bold {color}", justify="center")
    sub = Text("/ 100", style=FAINT, justify="center")

    filled = int(round(score / 100 * 24))
    bar = Text(justify="center")
    bar.append("█" * filled, style=color)
    bar.append("░" * (24 - filled), style=GRID)

    pill = Text(f" ● {level.upper()} ", style=f"bold {color} on {GRID}")

    body = Group(
        Align.center(big),
        Align.center(sub),
        Text(""),
        Align.center(bar),
        Text(""),
        Align.center(pill),
    )
    return Panel(Align(body, align="center", vertical="middle"),
                 title="[dim]THREAT SCORE[/]", title_align="left",
                 border_style=GRID, box=box.SQUARE)


def render_vitals_panel(os_metrics: dict) -> Panel:
    rows = Table.grid(padding=(0, 1))
    rows.add_column(width=10)
    rows.add_column(ratio=1)
    rows.add_column(width=6, justify="right")

    for label, key in (("CPU", "cpu_percent"), ("MEM", "mem_percent"), ("DISK C:", "disk_percent")):
        val = os_metrics.get(key, 0)
        try:
            pct = float(val)
        except (TypeError, ValueError):
            pct = 0.0
        width = 20
        filled = int(round(pct / 100 * width))
        bar = Text()
        bar.append("█" * filled, style=CYAN)
        bar.append("░" * (width - filled), style=GRID)
        rows.add_row(Text(label, style=DIM), bar, Text(f"{pct:.0f}%", style=BRIGHT))

    rows.add_row("", "", "")
    rows.add_row(Text("Uptime", style=FAINT), Text(str(os_metrics.get("uptime", "—")), style=DIM), "")
    return Panel(rows, title="[dim]SYSTEM VITALS[/]", title_align="left",
                 border_style=GRID, box=box.SQUARE)


def render_fleet_panel(fleet_raw: dict | None, agent_id: str | None, agent: dict) -> Panel:
    counts = _fleet_counts(fleet_raw)
    latest = _latest_report(agent)
    high_risk = 1 if latest and str(latest.get("risk_level", "")).lower() in ("high", "critical") else 0

    stats = Table.grid(padding=(0, 2), expand=True)
    stats.add_column(justify="center", ratio=1)
    stats.add_column(justify="center", ratio=1)
    stats.add_column(justify="center", ratio=1)

    def stat(n: int, label: str, color: str = BRIGHT) -> Text:
        t = Text(justify="center")
        t.append(f"{n}\n", style=f"bold {color}")
        t.append(label, style=FAINT)
        return t

    stats.add_row(
        stat(counts["online"], "ONLINE", MINT if counts["online"] else DIM),
        stat(counts["offline"], "OFFLINE"),
        stat(high_risk, "HIGH-RISK", RED if high_risk else DIM),
    )

    cycle = (latest or {}).get("cycle", "—")
    identity = agent.get("identity") or {}
    hostname = identity.get("hostname", agent_id or "—")
    agent_line = Text.assemble(
        ("AGENT ", DIM), (str(agent_id or "—"), CYAN), ("  ·  ", FAINT),
        (str(hostname), DIM), ("  ·  CYCLE #", FAINT), (str(cycle), DIM),
    )

    body = Group(stats, Text(""), agent_line)
    return Panel(body, title="[dim]FLEET[/]", title_align="left",
                 border_style=GRID, box=box.SQUARE)


def render_log_panel(agent: dict) -> Panel:
    entries = _log_entries(agent, limit=8)
    table = Table.grid(padding=(0, 2), expand=True)
    table.add_column(width=8)
    table.add_column(width=9)
    table.add_column(ratio=1)

    if not entries:
        table.add_row(Text("--:--:--", style=FAINT), Text("INFO", style=DIM),
                       Text("No events logged yet — awaiting first scan cycle.", style=DIM))
    for e in entries:
        ts = str(e.get("timestamp", ""))[11:19] or "--:--:--"
        sev = str(e.get("severity", "info")).lower()
        color = SEV_COLOR.get(sev, DIM)
        title = e.get("title", e.get("category", "event"))
        resolved = e.get("resolved")
        tag = "  [RESOLVED]" if resolved else ""
        msg = Text(title, style=BRIGHT if not resolved else DIM)
        if tag:
            msg.append(tag, style=MINT)
        table.add_row(Text(ts, style=FAINT), Text(sev.upper(), style=f"bold {color}"), msg)

    return Panel(table, title="[dim]THREAT LOG[/]", title_align="left",
                 border_style=GRID, box=box.SQUARE)


def render_header() -> Panel:
    now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    left = Text.assemble(("◈ NETWORK GUARDIAN  ", f"bold {CYAN}"), ("TAC-HUD", FAINT))
    right = Text.assemble(("● ", MINT), ("LIVE  ", DIM), (now, DIM))
    row = Table.grid(expand=True)
    row.add_column(ratio=1)
    row.add_column(justify="right")
    row.add_row(left, right)
    return Panel(row, border_style=GRID, box=box.SQUARE, height=3)


# ══════════════════════════════════════════════════════════════════
# LAYOUT + MAIN LOOP
# ══════════════════════════════════════════════════════════════════

def build_layout(fleet_raw: dict | None, os_metrics: dict, sweep_deg: float) -> Layout:
    agent_id, agent = _self_agent(fleet_raw)
    latest = _latest_report(agent)

    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="log", size=10),
    )
    layout["body"].split_row(
        Layout(name="radar", ratio=2, minimum_size=48),
        Layout(name="right", ratio=3),
    )
    layout["right"].split(
        Layout(name="toprow", size=11),
        Layout(name="fleet", size=8),
    )
    layout["toprow"].split_row(
        Layout(name="gauge"),
        Layout(name="vitals"),
    )

    layout["header"].update(render_header())
    layout["radar"].update(render_radar_panel(agent, sweep_deg))
    layout["gauge"].update(render_gauge_panel(latest))
    layout["vitals"].update(render_vitals_panel(os_metrics))
    layout["fleet"].update(render_fleet_panel(fleet_raw, agent_id, agent))
    layout["log"].update(render_log_panel(agent))
    return layout


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="ng-hud",
        description="Network Guardian TAC-HUD — live cyberpunk radar monitor for the terminal.",
    )
    parser.add_argument("--refresh", type=float, default=2.0,
                         help="Seconds between re-reading fleet.json (default: 2.0)")
    parser.add_argument("--fps", type=float, default=8.0,
                         help="Animation frame rate for the radar sweep (default: 8)")
    args = parser.parse_args(argv)

    if sys.platform == "win32":
        # Older cmd.exe / non-VT console hosts default to a legacy codepage
        # that can't encode the HUD's box-drawing and glyph characters —
        # switch to UTF-8 up front so Rich's Windows renderer doesn't choke.
        try:
            subprocess.run(["chcp", "65001"], shell=True, capture_output=True, check=False)
        except OSError:
            pass

    console = Console()
    telemetry = TelemetryAggregator()

    fleet_raw = _read_json(PATHS["fleet"])
    last_poll = time.monotonic()
    sweep_deg = 0.0
    deg_per_frame = 360.0 / max(1.0, 10.0 * args.fps)
    frame_delay = 1.0 / max(1.0, args.fps)

    try:
        with Live(console=console, screen=True, refresh_per_second=args.fps, transient=False) as live:
            while True:
                now = time.monotonic()
                if now - last_poll >= args.refresh:
                    fleet_raw = _read_json(PATHS["fleet"])
                    last_poll = now
                os_metrics = telemetry.get_os_metrics()
                live.update(build_layout(fleet_raw, os_metrics, sweep_deg))
                sweep_deg = (sweep_deg + deg_per_frame) % 360.0
                time.sleep(frame_delay)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
