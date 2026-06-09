"""
╔══════════════════════════════════════════════════════════════════╗
║  threat_report_engine.py  |  High-Fidelity Threat Brief Engine   ║
╠══════════════════════════════════════════════════════════════════╣
║  Consumes a TelemetryAggregator snapshot and produces a          ║
║  structured, human-readable terminal threat briefing.            ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import sys as _sys
from datetime import datetime
from typing import Any

from network_guardian.jarvis.telemetry_aggregator import TelemetryAggregator

# Operator name configurable via env var
_OPERATOR = os.environ.get("JARVIS_OPERATOR", "Network Guardian Operator")


# ══════════════════════════════════════════════════════════════════
# THRESHOLDS
# ══════════════════════════════════════════════════════════════════

class Thresholds:
    CPU_WARN        = 70.0
    CPU_CRIT        = 90.0
    MEM_WARN        = 75.0
    MEM_CRIT        = 90.0
    DISK_WARN       = 80.0
    DISK_CRIT       = 95.0
    INJECTION_WARN  = 5
    INJECTION_CRIT  = 20
    LATERAL_WARN    = 1
    LATERAL_CRIT    = 5


# ══════════════════════════════════════════════════════════════════
# ANSI COLOUR HELPERS
# ══════════════════════════════════════════════════════════════════

_COLOUR = hasattr(_sys.stdout, "isatty") and _sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"{code}{text}\033[0m" if _COLOUR else text

def _red(t):    return _c("\033[91m", t)
def _yellow(t): return _c("\033[93m", t)
def _green(t):  return _c("\033[92m", t)
def _cyan(t):   return _c("\033[96m", t)
def _bold(t):   return _c("\033[1m",  t)
def _dim(t):    return _c("\033[2m",  t)


# ══════════════════════════════════════════════════════════════════
# SCORING HELPERS
# ══════════════════════════════════════════════════════════════════

def _safe_float(v: Any) -> float:
    try:
        return float(str(v).replace("%", "").strip())
    except (ValueError, TypeError):
        return 0.0


def _scale(value: float, warn: float, crit: float, max_pts: float) -> float:
    if value <= warn:
        return 0.0
    if value >= crit:
        return float(max_pts)
    return ((value - warn) / (crit - warn)) * max_pts


def _score_to_label(score: int) -> str:
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "ELEVATED"
    return "NOMINAL"


def _badge(value: Any, warn: float, crit: float) -> str:
    try:
        v = float(str(value).replace("%", "").strip())
    except (ValueError, TypeError):
        return _dim("UNKNOWN")
    if v >= crit:   return _red("CRITICAL")
    if v >= warn:   return _yellow("ELEVATED")
    return _green("NOMINAL")


# ══════════════════════════════════════════════════════════════════
# THREAT REPORT ENGINE
# ══════════════════════════════════════════════════════════════════

class ThreatReportEngine:
    """
    Wraps a TelemetryAggregator and renders a formatted situation report.

    Parameters
    ----------
    telemetry : TelemetryAggregator instance.
    operator  : Operator name shown in the report header.
                Defaults to the ``JARVIS_OPERATOR`` env var.
    """

    def __init__(
        self,
        telemetry: TelemetryAggregator,
        operator: str | None = None,
    ) -> None:
        self._tel      = telemetry
        self._operator = operator or _OPERATOR

    # ── Public interface ──────────────────────────────────────────

    def print_summary(self) -> None:
        snapshot = self._tel.full_snapshot()
        lines    = self._build_report(snapshot)
        print("\n" + "\n".join(lines) + "\n")

    def compute_threat_level(self) -> tuple[str, int]:
        """Return (label, score) where score 0-100."""
        snap  = self._tel.full_snapshot()
        score = self._score_snapshot(snap)
        label = _score_to_label(score)
        return label, score

    def build_report_lines(self) -> list[str]:
        """Return the report as a list of strings (no print side-effect)."""
        return self._build_report(self._tel.full_snapshot())

    # ── Report builder ────────────────────────────────────────────

    def _build_report(self, snap: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        ts    = snap.get("timestamp", datetime.now().isoformat())
        score = self._score_snapshot(snap)
        label = _score_to_label(score)
        _bar  = "─" * 64

        lines += [
            _cyan(_bold(f"{'─'*26}  SITUATION REPORT  {'─'*19}")),
            _dim(f"  Generated : {ts}"),
            _dim(f"  Operator  : {self._operator}"),
            _bar,
        ]

        colour_fn = {"NOMINAL": _green, "ELEVATED": _yellow,
                     "HIGH": _yellow, "CRITICAL": _red}.get(label, _cyan)
        lines += [
            "",
            f"  {_bold('THREAT LEVEL')}  :  {colour_fn(_bold(label))}  "
            f"({_dim(f'score {score}/100')})",
            "",
            _bar,
        ]

        lines.append(_bold("  ◈  SYSTEM RESOURCES"))
        os_m = snap.get("os_metrics", {})
        if "error" in os_m:
            lines.append(f"    {_red('ERROR')} : {os_m['error']}")
        else:
            lines += self._render_os(os_m)
        lines.append(_bar)

        lines.append(_bold("  ◈  FLEET STATUS"))
        fleet = snap.get("fleet", {})
        if "error" in fleet:
            lines.append(f"    {_red('ERROR')} : {fleet['error']}")
        else:
            lines += self._render_fleet(fleet)
        lines.append(_bar)

        lines.append(_bold("  ◈  INTRUSION ATTEMPTS  (Firewall / SQLi)"))
        inj = snap.get("injection", {})
        if "error" in inj:
            lines.append(f"    {_red('ERROR')} : {inj['error']}")
        else:
            lines += self._render_injection(inj)
        lines.append(_bar)

        lines.append(_bold("  ◈  LATERAL MOVEMENT"))
        lat = snap.get("lateral", {})
        if "error" in lat:
            lines.append(f"    {_red('ERROR')} : {lat['error']}")
        else:
            lines += self._render_lateral(lat)
        lines.append(_bar)

        recs = self._recommendations(snap, score)
        if recs:
            lines.append(_bold("  ◈  RECOMMENDED ACTIONS"))
            for i, rec in enumerate(recs, 1):
                lines.append(f"    {_dim(str(i)+'.')}  {rec}")
            lines.append(_bar)

        return lines

    # ── Section renderers ─────────────────────────────────────────

    def _render_os(self, m: dict) -> list[str]:
        lines = []
        for name, key, warn, crit in [
            ("CPU",     "cpu_percent",  Thresholds.CPU_WARN,  Thresholds.CPU_CRIT),
            ("Memory",  "mem_percent",  Thresholds.MEM_WARN,  Thresholds.MEM_CRIT),
            ("Disk C:", "disk_percent", Thresholds.DISK_WARN, Thresholds.DISK_CRIT),
        ]:
            val = m.get(key, "N/A")
            lines.append(f"    {name:<12}  {_bold(str(val)+'%'):<8}  {_badge(val, warn, crit)}")
        lines += [
            f"    {'Memory Used':<12}  {m.get('mem_used','N/A')} / {m.get('mem_total','N/A')}",
            f"    {'Disk Free':<12}  {m.get('disk_free','N/A')}",
            f"    {'Processes':<12}  {m.get('proc_count','N/A')}",
            f"    {'Uptime':<12}  {m.get('uptime','N/A')}",
            f"    {'Boot Time':<12}  {m.get('boot_time','N/A')}",
        ]
        return lines

    def _render_fleet(self, f: dict) -> list[str]:
        risky = f.get("high_risk_ips", [])
        return [
            f"    Total Devices  :  {_bold(str(f.get('total', 0)))}",
            f"    Online         :  {_green(str(f.get('online', 0)))}",
            f"    Offline        :  {_dim(str(f.get('offline', 0)))}",
            f"    Unknown        :  {_yellow(str(f.get('unknown', 0)))}",
            f"    High-Risk IPs  :  "
            + (_red(', '.join(str(x) for x in risky)) if risky else _green("None detected")),
        ]

    def _render_injection(self, inj: dict) -> list[str]:
        total   = inj.get("total_fetched", 0)
        blocked = inj.get("blocked_count", 0)
        lines   = [
            f"    Total Recorded :  {_bold(str(total))}  "
            f"{_badge(total, Thresholds.INJECTION_WARN, Thresholds.INJECTION_CRIT)}",
            f"    Blocked        :  {_green(str(blocked))}",
        ]
        for t, count in inj.get("top_attack_types", []):
            lines.append(f"      {_dim('·')}  {t:<30}  {count} hit(s)")
        for ip, count in inj.get("top_source_ips", []):
            lines.append(f"      {_dim('·')}  {ip:<22}  {count} attempt(s)")
        return lines

    def _render_lateral(self, lat: dict) -> list[str]:
        total    = lat.get("total", 0)
        critical = lat.get("critical", 0)
        high     = lat.get("high", 0)
        recent   = lat.get("recent_24h", 0)
        return [
            f"    Total Events   :  {_bold(str(total))}  "
            f"{_badge(total, Thresholds.LATERAL_WARN, Thresholds.LATERAL_CRIT)}",
            f"    Critical       :  {(_red if critical else _green)(str(critical))}",
            f"    High           :  {(_yellow if high else _green)(str(high))}",
            f"    Medium         :  {str(lat.get('medium', 0))}",
            f"    Low            :  {_dim(str(lat.get('low', 0)))}",
            f"    Last 24 Hours  :  {(_yellow if recent else _green)(str(recent))}",
        ]

    # ── Scoring ───────────────────────────────────────────────────

    def _score_snapshot(self, snap: dict[str, Any]) -> int:
        score = 0
        os_m = snap.get("os_metrics", {})
        if "error" not in os_m:
            score += _scale(_safe_float(os_m.get("cpu_percent",  0)), Thresholds.CPU_WARN,  Thresholds.CPU_CRIT,  8)
            score += _scale(_safe_float(os_m.get("mem_percent",  0)), Thresholds.MEM_WARN,  Thresholds.MEM_CRIT,  8)
            score += _scale(_safe_float(os_m.get("disk_percent", 0)), Thresholds.DISK_WARN, Thresholds.DISK_CRIT, 9)
        fleet = snap.get("fleet", {})
        if "error" not in fleet:
            score += min(len(fleet.get("high_risk_ips", [])) * 5, 15)
        inj = snap.get("injection", {})
        if "error" not in inj:
            score += _scale(_safe_float(inj.get("total_fetched", 0)),
                            Thresholds.INJECTION_WARN, Thresholds.INJECTION_CRIT, 35)
        lat = snap.get("lateral", {})
        if "error" not in lat:
            score += min(lat.get("critical", 0) * 10 + lat.get("high", 0) * 5, 25)
        return min(int(score), 100)

    # ── Recommendations ───────────────────────────────────────────

    def _recommendations(self, snap: dict, score: int) -> list[str]:
        recs: list[str] = []
        os_m = snap.get("os_metrics", {})
        if "error" not in os_m:
            if _safe_float(os_m.get("cpu_percent", 0)) >= Thresholds.CPU_CRIT:
                recs.append("CPU critical — investigate high-CPU processes for cryptominers.")
            if _safe_float(os_m.get("mem_percent", 0)) >= Thresholds.MEM_WARN:
                recs.append("Memory pressure elevated — consider closing unused applications.")
        inj = snap.get("injection", {})
        if "error" not in inj and inj.get("total_fetched", 0) >= Thresholds.INJECTION_CRIT:
            recs.append("High injection volume detected — review firewall rules and WAF config.")
        lat = snap.get("lateral", {})
        if "error" not in lat and lat.get("critical", 0) > 0:
            recs.append("Critical lateral movement events recorded — initiate incident response.")
        if score >= 70:
            recs.append("CRITICAL threat level — run a full TriageAgent SYSTEM_AUDIT immediately.")
        elif score >= 45:
            recs.append("Elevated threat — consider running a THREAT_HUNT scan via Jarvis.")
        return recs
