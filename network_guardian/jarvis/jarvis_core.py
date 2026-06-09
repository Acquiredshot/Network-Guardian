"""
╔══════════════════════════════════════════════════════════════════╗
║          J.A.R.V.I.S  —  Network Guardian Terminal Layer        ║
║          jarvis_core.py  |  Master Shell + Intent Parser         ║
╠══════════════════════════════════════════════════════════════════╣
║  Role     : Primary REPL — routes all commands to subsystems     ║
║  Extended : LangGraph + DeepSeek triage integration              ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from network_guardian.jarvis.telemetry_aggregator import TelemetryAggregator
from network_guardian.jarvis.subsystem_bootstrapper import SubsystemBootstrapper
from network_guardian.jarvis.threat_report_engine import ThreatReportEngine
from network_guardian.jarvis.probe_commander import (
    list_registered_probes,
    run_full_probe_report,
    ProbeReport,
)

# Voice + ear are optional (Windows-only hardware deps)
try:
    from network_guardian.jarvis.jarvis_voice import JarvisVoice, VoiceConfig
    _VOICE_AVAILABLE = True
except Exception:
    _VOICE_AVAILABLE = False

try:
    from network_guardian.jarvis.jarvis_ear import JarvisEar, EarConfig
    _EAR_AVAILABLE = True
except Exception:
    _EAR_AVAILABLE = False

# LangGraph reasoner (optional — active when DEEPSEEK_API_KEY is set)
try:
    from network_guardian.ai.langgraph_reasoner import reason_about_intent as _lg_reason
    _LG_AVAILABLE = True
except ImportError:
    _LG_AVAILABLE = False
    _lg_reason = None  # type: ignore[assignment]

# Conversational intelligence layer
try:
    from network_guardian.jarvis.jarvis_conversation import (
        get_spoken_summary as _get_spoken_summary,
        get_chat_reply as _get_chat_reply,
    )
    _CONV_AVAILABLE = True
except Exception:
    _CONV_AVAILABLE = False
    def _get_spoken_summary(*a, **kw) -> str: return ""          # type: ignore
    def _get_chat_reply(*a, **kw) -> str: return ""               # type: ignore

_OPERATOR = os.environ.get("JARVIS_OPERATOR", "Network Guardian Operator")

# Last triage result — populated by cmd_triage so dispatch can speak it
_LAST_TRIAGE: dict = {}

# ══════════════════════════════════════════════════════════════════
# MODULE-LEVEL SINGLETONS
# One TelemetryAggregator + ThreatReportEngine shared by all handlers
# so the background CPU sampler is already warm by the first command.
# ══════════════════════════════════════════════════════════════════

_TELEMETRY: TelemetryAggregator | None = None
_REPORT:    ThreatReportEngine  | None = None


def _tel() -> TelemetryAggregator:
    global _TELEMETRY
    if _TELEMETRY is None:
        _TELEMETRY = TelemetryAggregator()
    return _TELEMETRY


def _rep() -> ThreatReportEngine:
    global _REPORT
    if _REPORT is None:
        _REPORT = ThreatReportEngine(_tel())
    return _REPORT

# ══════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════

BANNER = r"""
     ██╗ █████╗ ██████╗ ██╗   ██╗██╗███████╗
     ██║██╔══██╗██╔══██╗██║   ██║██║██╔════╝
     ██║███████║██████╔╝██║   ██║██║███████╗
██   ██║██╔══██║██╔══██╗╚██╗ ██╔╝██║╚════██║
╚█████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║███████║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝
   Just A Rather Very Intelligent System
   Network Guardian — Threat Intelligence Layer
"""

SEPARATOR = "─" * 64
VERSION   = "2.0.0"
PROMPT    = "jarvis > "

INTENT_MAP: dict[str, str] = {
    # Situation / threat overview
    "situation":            "cmd_situation",
    "status":               "cmd_situation",
    "threat":               "cmd_situation",
    "health":               "cmd_situation",
    "overview":             "cmd_situation",
    "what's going on":      "cmd_situation",
    "assessment":           "cmd_situation",
    "how safe":             "cmd_situation",
    "are we safe":          "cmd_situation",
    "network status":       "cmd_situation",
    "threat level":         "cmd_situation",
    "current threat":       "cmd_situation",
    "security status":      "cmd_situation",
    "security report":      "cmd_situation",
    # Defense activation
    "start":                "cmd_start",
    "activate":             "cmd_start",
    "launch":               "cmd_start",
    "turn on":              "cmd_start",
    "deploy":               "cmd_start",
    "boot":                 "cmd_start",
    "defenses":             "cmd_start",
    # Defense shutdown
    "halt":                 "cmd_stop",
    "turn off":             "cmd_stop",
    "kill":                 "cmd_stop",
    # Fleet report
    "fleet":                "cmd_fleet",
    "devices":              "cmd_fleet",
    "nodes":                "cmd_fleet",
    "hosts":                "cmd_fleet",
    "network map":          "cmd_fleet",
    "how many devices":     "cmd_fleet",
    "list devices":         "cmd_fleet",
    "show devices":         "cmd_fleet",
    "connected devices":    "cmd_fleet",
    "registered devices":   "cmd_fleet",
    "what devices":         "cmd_fleet",
    "which devices":        "cmd_fleet",
    # Firewall / injection history
    "firewall":             "cmd_firewall",
    "injection":            "cmd_firewall",
    "sql":                  "cmd_firewall",
    "attacks":              "cmd_firewall",
    "blocked":              "cmd_firewall",
    "last scan":            "cmd_firewall",
    "last firewall":        "cmd_firewall",
    "firewall scan":        "cmd_firewall",
    "last attack":          "cmd_firewall",
    "recent attacks":       "cmd_firewall",
    "recent injection":     "cmd_firewall",
    "attack history":       "cmd_firewall",
    "intrusion":            "cmd_firewall",
    "intrusions":           "cmd_firewall",
    "when was the last":    "cmd_firewall",
    "last time":            "cmd_firewall",
    "show attacks":         "cmd_firewall",
    "show firewall":        "cmd_firewall",
    "scan history":         "cmd_firewall",
    # Lateral movement
    "lateral":              "cmd_lateral",
    "movement":             "cmd_lateral",
    "pivot":                "cmd_lateral",
    "spread":               "cmd_lateral",
    "lateral movement":     "cmd_lateral",
    "network spread":       "cmd_lateral",
    "pivoting":             "cmd_lateral",
    # Active probes / field agents
    "probe":                "cmd_probes",
    "probes":               "cmd_probes",
    "field agent":          "cmd_probes",
    "field agents":         "cmd_probes",
    "remote agent":         "cmd_probes",
    "remote agents":        "cmd_probes",
    "active probe":         "cmd_probes",
    "active probes":        "cmd_probes",
    "show probes":          "cmd_probes",
    "list probes":          "cmd_probes",
    "find probes":          "cmd_probes",
    "scan probes":          "cmd_probes",
    "probe scan":           "cmd_probes",
    "probe status":         "cmd_probes",
    "agent status":         "cmd_probes",
    "my laptop":            "cmd_probes",
    "other operators":      "cmd_probes",
    # Probe health check
    "probe health":         "cmd_probe_health",
    "agent health":         "cmd_probe_health",
    "check probe":          "cmd_probe_health",
    "check probes":         "cmd_probe_health",
    "ping probe":           "cmd_probe_health",
    "is the probe":         "cmd_probe_health",
    "is my probe":          "cmd_probe_health",
    # System metrics
    "cpu":                  "cmd_metrics",
    "memory":               "cmd_metrics",
    "ram":                  "cmd_metrics",
    "disk":                 "cmd_metrics",
    "metrics":              "cmd_metrics",
    "resources":            "cmd_metrics",
    "performance":          "cmd_metrics",
    "system health":        "cmd_metrics",
    "resource usage":       "cmd_metrics",
    "how much memory":      "cmd_metrics",
    "disk space":           "cmd_metrics",
    "cpu usage":            "cmd_metrics",
    # Deep-AI triage (LangGraph + DeepSeek)
    "triage":               "cmd_triage",
    "analyze":              "cmd_triage",
    "analyse":              "cmd_triage",
    "deep scan":            "cmd_triage",
    "ai scan":              "cmd_triage",
    "reason":               "cmd_triage",
    "investigate":          "cmd_triage",
    "deep analysis":        "cmd_triage",
    "run a scan":           "cmd_triage",
    "full scan":            "cmd_triage",
    "scan for threats":     "cmd_triage",
    # Help
    "help":                 "cmd_help",
    "commands":             "cmd_help",
    "?":                    "cmd_help",
    "what can you do":      "cmd_help",
    "what commands":        "cmd_help",
    # Exit  (deliberate phrases only — "bye" removed to prevent mic mishearing)
    "jarvis exit":          "cmd_exit",
    "jarvis shutdown":      "cmd_exit",
    "jarvis terminate":     "cmd_exit",
    "shut down jarvis":     "cmd_exit",
    "terminate jarvis":     "cmd_exit",
}


# ══════════════════════════════════════════════════════════════════
# TERMINAL UTILITIES
# ══════════════════════════════════════════════════════════════════

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class C:
    _ON    = _supports_color()
    RESET  = "\033[0m"  if _ON else ""
    BOLD   = "\033[1m"  if _ON else ""
    DIM    = "\033[2m"  if _ON else ""
    CYAN   = "\033[96m" if _ON else ""
    GREEN  = "\033[92m" if _ON else ""
    YELLOW = "\033[93m" if _ON else ""
    RED    = "\033[91m" if _ON else ""
    MAGENTA= "\033[95m" if _ON else ""
    WHITE  = "\033[97m" if _ON else ""
    BLUE   = "\033[94m" if _ON else ""


def print_banner() -> None:
    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    print(f"{C.CYAN}{C.BOLD}")
    for line in BANNER.strip("\n").splitlines():
        print(line.center(min(term_width, 80)))
    print(C.RESET)
    ts = datetime.now().strftime("%A, %d %B %Y  |  %H:%M:%S")
    ds_status = f"{C.GREEN}DeepSeek ACTIVE{C.RESET}" if (
        _LG_AVAILABLE and os.environ.get("DEEPSEEK_API_KEY")
    ) else f"{C.YELLOW}DeepSeek OFFLINE{C.RESET}"
    print(f"{C.DIM}  Version {VERSION}    {ts}{C.RESET}")
    print(f"{C.DIM}  AI Engine: {ds_status}")
    print(f"{C.DIM}  {SEPARATOR}{C.RESET}\n")


def jarvis_say(msg: str, level: str = "info") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    prefix_map = {
        "info":    f"{C.CYAN}[JARVIS {ts}]{C.RESET}",
        "ok":      f"{C.GREEN}[  OK   {ts}]{C.RESET}",
        "warn":    f"{C.YELLOW}[ WARN  {ts}]{C.RESET}",
        "error":   f"{C.RED}[ ERR   {ts}]{C.RESET}",
        "data":    f"{C.MAGENTA}[ DATA  {ts}]{C.RESET}",
        "section": f"{C.BOLD}{C.WHITE}",
        "ai":      f"{C.BLUE}[  AI   {ts}]{C.RESET}",
    }
    prefix = prefix_map.get(level, prefix_map["info"])
    if level == "section":
        print(f"\n{prefix}{'─'*6}  {msg}  {'─'*6}{C.RESET}")
    else:
        print(f"  {prefix}  {msg}")


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    def _row_str(cells):
        return "  " + "  ".join(
            f"{C.WHITE}{str(c):<{col_widths[i]}}{C.RESET}"
            for i, c in enumerate(cells)
        )

    hr = "  " + "  ".join("─" * w for w in col_widths)
    print(f"\n{C.DIM}{_row_str(headers)}{C.RESET}")
    print(f"{C.DIM}{hr}{C.RESET}")
    for row in rows:
        print(_row_str(row))
    print()


def _level_badge(value: float, warn_thresh: float, crit_thresh: float) -> str:
    if value >= crit_thresh:
        return f"{C.RED}CRITICAL{C.RESET}"
    if value >= warn_thresh:
        return f"{C.YELLOW}WARNING{C.RESET}"
    return f"{C.GREEN}NOMINAL{C.RESET}"


# ══════════════════════════════════════════════════════════════════
# INTENT PARSER
# ══════════════════════════════════════════════════════════════════

def parse_intent(raw: str) -> str | None:
    """
    Map free-form natural-language input to an internal command key.
    Longest keyword match wins.
    """
    text = raw.strip().lower()
    if not text:
        return None
    best_len, best_cmd = 0, None
    for keyword, command in INTENT_MAP.items():
        if keyword in text and len(keyword) > best_len:
            best_len, best_cmd = len(keyword), command
    return best_cmd


def _build_live_context() -> str:
    """
    Build a compact, human-readable snapshot of current system state
    to pass as context to the conversational AI so it can answer
    fact-based questions with real data.

    Scope is intentionally minimal — read-only telemetry only.
    """
    lines: list[str] = []
    try:
        # ── Threat level ──────────────────────────────────────────
        label, score = _rep().compute_threat_level()
        lines.append(f"Current threat level: {label} (score {score:.0f}/100)")

        # ── OS metrics ────────────────────────────────────────────
        m = _tel().get_os_metrics()
        lines.append(
            f"System: CPU {m.get('cpu_percent','?')}%  "
            f"RAM {m.get('mem_percent','?')}%  "
            f"Disk {m.get('disk_percent','?')}%  "
            f"Uptime {m.get('uptime','?')}"
        )

        # ── Fleet ─────────────────────────────────────────────────
        fs = _tel().fleet_summary()
        lines.append(
            f"Fleet: {fs.get('total',0)} devices registered  "
            f"({fs.get('online',0)} online, {fs.get('offline',0)} offline)"
        )
        if fs.get("high_risk_ips"):
            lines.append(f"High-risk IPs: {', '.join(str(ip) for ip in fs['high_risk_ips'][:5])}")

        # ── Firewall / injection ──────────────────────────────────
        inj = _tel().injection_summary()
        total_inj = inj.get("total_fetched", 0)
        blocked   = inj.get("blocked_count", 0)
        lines.append(
            f"Firewall: {total_inj} injection records total  ({blocked} blocked)"
        )
        # Most recent event timestamp
        recent_recs = _tel().read_injection_history(limit=1)
        if recent_recs:
            r = recent_recs[0]
            ts  = r.get("timestamp", r.get("created_at", r.get("time", "unknown time")))
            atype = r.get("attack_type", r.get("type", "unknown type"))
            src   = r.get("source_ip",   r.get("ip",   "unknown source"))
            lines.append(f"Last firewall event: {ts}  type={atype}  source={src}")
        else:
            lines.append("Last firewall event: no records found")

        # ── Lateral movement ──────────────────────────────────────
        ls = _tel().lateral_summary()
        sev = ls.get("severity_counts", {})
        recent_lat = ls.get("recent_24h", 0)
        high_lat   = sev.get("HIGH", 0) + sev.get("CRITICAL", 0)
        lines.append(
            f"Lateral movement: {sum(sev.values())} events total  "
            f"{high_lat} HIGH/CRITICAL  {recent_lat} in last 24h"
        )

        # ── Probe agents ──────────────────────────────────────────
        probes = list_registered_probes()
        online_p = [p for p in probes if p.status == "online"]
        stale_p  = [p for p in probes if p.status == "stale"]
        lines.append(
            f"Field probes: {len(probes)} registered  "
            f"({len(online_p)} online, {len(stale_p)} stale, "
            f"{len(probes) - len(online_p) - len(stale_p)} offline)"
        )
        for p in probes:
            lines.append(
                f"  Probe '{p.hostname}' ip={p.ip or '?'} "
                f"status={p.status} last_seen={p.last_seen}"
            )

    except Exception as exc:
        lines.append(f"(partial telemetry — {exc})")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ══════════════════════════════════════════════════════════════════

def cmd_situation(_args: str) -> None:
    jarvis_say("SITUATION ASSESSMENT — compiling intelligence...", "section")
    try:
        _rep().print_summary()
    except Exception as exc:
        jarvis_say(f"Situation report failed: {exc}", "error")


def cmd_start(_args: str) -> None:
    jarvis_say("ACTIVATING DEFENSES — initiating boot sequence...", "section")
    try:
        SubsystemBootstrapper().launch()
    except Exception as exc:
        jarvis_say(f"Boot sequence failed: {exc}", "error")


def cmd_stop(_args: str) -> None:
    jarvis_say("HALTING DEFENSES — sending shutdown signal...", "section")
    try:
        SubsystemBootstrapper().shutdown()
    except Exception as exc:
        jarvis_say(f"Shutdown failed: {exc}", "error")


def cmd_fleet(_args: str) -> None:
    jarvis_say("FLEET INTELLIGENCE — reading device registry...", "section")
    try:
        data = _tel().read_fleet()

        # ── Passive devices (the devices[] array) ────────────────
        devices: list = []
        if data:
            devices = data if isinstance(data, list) else data.get("devices", [])
            if devices:
                rows = [[str(d.get("id", d.get("mac", "—"))),
                         str(d.get("hostname", d.get("name", "—"))),
                         str(d.get("ip", "—")),
                         str(d.get("status", "—")),
                         str(d.get("last_seen", "—"))] for d in devices]
                jarvis_say(f"Passive devices ({len(rows)}):", "info")
                print_table(["ID/MAC", "HOSTNAME", "IP", "STATUS", "LAST SEEN"], rows)

        # ── Registered probe agents (the agents{} section) ───────
        probes = list_registered_probes()
        if probes:
            p_rows = [[p.agent_id[:24], p.hostname, p.ip or "?",
                       p.status, p.last_seen] for p in probes]
            jarvis_say(f"Registered probe agents ({len(p_rows)}):", "info")
            print_table(["AGENT ID", "HOSTNAME", "IP", "STATUS", "LAST SEEN"], p_rows)

        total = len(devices) + len(probes)
        if total == 0:
            jarvis_say("fleet.json is empty or not found.", "warn")
        else:
            online = sum(1 for p in probes if p.status == "online")
            jarvis_say(
                f"{len(devices)} passive device(s)  |  "
                f"{len(probes)} probe agent(s) ({online} online).",
                "ok",
            )
    except Exception as exc:
        jarvis_say(f"Fleet read failed: {exc}", "error")


def cmd_firewall(_args: str) -> None:
    jarvis_say("FIREWALL INTELLIGENCE — querying injection history...", "section")
    try:
        records   = _tel().read_injection_history(limit=15)
        if not records:
            jarvis_say("No injection records found.", "warn")
            return
        rows = [[str(r.get(k, "—")) for k in
                 ("timestamp", "source_ip", "attack_type", "payload_snippet", "blocked")]
                for r in records]
        print_table(["TIMESTAMP", "SOURCE IP", "ATTACK TYPE", "PAYLOAD SNIPPET", "BLOCKED"], rows)
        jarvis_say(f"{len(records)} record(s) retrieved (latest 15 shown).", "ok")
    except Exception as exc:
        jarvis_say(f"Firewall query failed: {exc}", "error")


def cmd_lateral(_args: str) -> None:
    jarvis_say("LATERAL MOVEMENT SCAN — reading pivot event log...", "section")
    try:
        events    = _tel().read_lateral_movement()
        if not events:
            jarvis_say("No lateral movement events on record.", "ok")
            return
        evlist = events if isinstance(events, list) else events.get("events", [])
        rows   = [[str(e.get(k, "—")) for k in
                   ("timestamp", "source", "destination", "technique", "severity")]
                  for e in evlist]
        print_table(["TIMESTAMP", "SOURCE", "DESTINATION", "TECHNIQUE", "SEVERITY"], rows)
        high = sum(1 for e in evlist if str(e.get("severity", "")).upper() in ("HIGH", "CRITICAL"))
        jarvis_say(f"{len(evlist)} event(s) total — {high} HIGH/CRITICAL.",
                   "error" if high > 0 else "ok")
    except Exception as exc:
        jarvis_say(f"Lateral movement read failed: {exc}", "error")


def cmd_metrics(_args: str) -> None:
    jarvis_say("SYSTEM METRICS — sampling hardware telemetry...", "section")
    try:
        m = _tel().get_os_metrics()

        def _safe_f(v):
            try: return float(str(v).replace("%", ""))
            except: return 0.0

        rows = [
            ["CPU Usage",       f"{m['cpu_percent']}%",  _level_badge(_safe_f(m['cpu_percent']), 70, 90)],
            ["Memory Usage",    f"{m['mem_percent']}%",  _level_badge(_safe_f(m['mem_percent']), 75, 90)],
            ["Memory Used",     m['mem_used'],            "—"],
            ["Disk Usage",      f"{m['disk_percent']}%", _level_badge(_safe_f(m['disk_percent']), 80, 95)],
            ["Disk Free",       m['disk_free'],           "—"],
            ["Active Procs",    str(m['proc_count']),     "—"],
            ["Uptime",          m['uptime'],              "—"],
        ]
        print_table(["METRIC", "VALUE", "STATE"], rows)
    except Exception as exc:
        jarvis_say(f"Metrics read failed: {exc}", "error")


def cmd_triage(raw: str) -> None:
    """
    Deep AI triage via LangGraph + DeepSeek-R1.

    Passes the raw command as intent to the reasoner, collects the
    action plan and recommendations, and presents them in the terminal.
    Falls back to a standard situation report if DeepSeek is unavailable.
    """
    jarvis_say("DEEP AI TRIAGE — invoking LangGraph + DeepSeek reasoner...", "section")

    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not _LG_AVAILABLE or not api_key:
        jarvis_say(
            "LangGraph/DeepSeek not active. "
            "Set DEEPSEEK_API_KEY to enable deep reasoning. "
            "Falling back to telemetry-based situation report.",
            "warn",
        )
        cmd_situation(raw)
        return

    # Collect current telemetry as system state context
    try:
        snap = _tel().full_snapshot()
    except Exception:
        snap = {}

    try:
        result = asyncio.run(
            _lg_reason(
                intent=raw,
                system_state=snap,
                observations={},
                api_key=api_key,
            )
        )
    except Exception as exc:
        jarvis_say(f"DeepSeek call failed: {exc}", "error")
        return

    # Store for voice summary in dispatch
    global _LAST_TRIAGE
    _LAST_TRIAGE = dict(result)

    # ── Print reasoning ──
    reasoning = result.get("deepseek_reasoning", "")
    if reasoning:
        summary_line = reasoning.split("\n")[0][:200]
        jarvis_say(f"AI Reasoning: {summary_line}", "ai")

    # ── Print intent classification ──
    intent_class = result.get("intent_class", "UNKNOWN")
    confidence   = result.get("confidence", 0.0)
    jarvis_say(
        f"Intent classified as {C.CYAN}{intent_class}{C.RESET} "
        f"(confidence {confidence:.0%})",
        "ai",
    )

    # ── Print action plan ──
    plan = result.get("action_plan", [])
    if plan:
        jarvis_say(f"Action plan — {len(plan)} step(s):", "ai")
        for i, step in enumerate(plan, 1):
            jarvis_say(f"  {i}. [{step.get('agent','?')}]  {step.get('action','')}", "data")

    # ── Print recommendations ──
    recs = result.get("recommendations", [])
    if recs:
        jarvis_say("Recommendations:", "ai")
        for i, rec in enumerate(recs, 1):
            jarvis_say(f"  {i}. {rec}", "data")

    if result.get("error") and result["error"] not in ("", "no_api_key"):
        jarvis_say(f"Partial error during reasoning: {result['error']}", "warn")


def cmd_probes(_args: str) -> None:
    jarvis_say("PROBE COMMANDER — scanning for active field agents...", "section")
    try:
        report = run_full_probe_report()
    except Exception as exc:
        jarvis_say(f"Probe scan failed: {exc}", "error")
        return

    # ── Registered agents ────────────────────────────────────────
    if report.registered:
        rows = [[p.agent_id[:24], p.hostname, p.ip or "?",
                 p.status, p.last_seen] for p in report.registered]
        jarvis_say(f"Registered probe agents ({len(rows)}):", "info")
        print_table(["AGENT ID", "HOSTNAME", "IP", "STATUS", "LAST SEEN"], rows)
    else:
        jarvis_say("No agents registered in fleet.json yet.", "warn")

    # ── Health of registered probes ──────────────────────────────
    if report.health:
        h_rows = [[
            h.ip,
            f"{h.latency_ms:.0f} ms" if h.latency_ms is not None else "—",
            "YES" if h.reachable else "NO",
            ", ".join(str(p) for p in h.open_ports) or "none",
            "NG" if h.is_ng_base else "",
        ] for h in report.health]
        jarvis_say("Probe health checks:", "info")
        print_table(["IP", "LATENCY", "REACHABLE", "OPEN PORTS", "NG?"], h_rows)

    # ── Newly discovered (unregistered) hosts ────────────────────
    if report.discovered:
        d_rows = [[d.ip, d.hostname,
                   str(d.port) if d.port else "?",
                   "YES" if d.is_ng_base else "MAYBE"] for d in report.discovered]
        jarvis_say(f"Unregistered probe candidates found on {report.scanned_subnet}:", "warn")
        print_table(["IP", "HOSTNAME", "PORT", "NG BASE?"], d_rows)
        jarvis_say(
            "Tip: ensure those probes point their --base URL at this machine to register.",
            "info",
        )
    else:
        jarvis_say(
            f"No unregistered probes detected on {report.scanned_subnet}.",
            "ok",
        )

    online = sum(1 for p in report.registered if p.status == "online")
    jarvis_say(
        f"Scan complete in {report.scan_duration_s}s — "
        f"{len(report.registered)} registered, "
        f"{online} online, "
        f"{len(report.discovered)} unregistered candidate(s).",
        "ok",
    )


def cmd_probe_health(_args: str) -> None:
    jarvis_say("PROBE HEALTH CHECK — pinging all known field agents...", "section")
    try:
        probes = list_registered_probes()
        if not probes:
            jarvis_say("No agents in fleet.json to health-check.", "warn")
            return

        import asyncio
        from network_guardian.jarvis.probe_commander import health_check_probe

        async def _run_checks() -> list:
            tasks = [health_check_probe(p.ip) for p in probes if p.ip]
            return list(await asyncio.gather(*tasks, return_exceptions=False))

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                fut = asyncio.run_coroutine_threadsafe(_run_checks(), loop)
                results = fut.result(timeout=20)
            else:
                results = loop.run_until_complete(_run_checks())
        except RuntimeError:
            results = asyncio.run(_run_checks())

        rows = [[
            h.ip,
            f"{h.latency_ms:.0f} ms" if h.latency_ms is not None else "—",
            "REACHABLE" if h.reachable else "UNREACHABLE",
            ", ".join(str(p) for p in h.open_ports) or "none",
            "NG" if h.is_ng_base else "",
            h.error or "",
        ] for h in results]
        print_table(["IP", "LATENCY", "STATUS", "OPEN PORTS", "NG?", "NOTE"], rows)
        reachable = sum(1 for h in results if h.reachable)
        jarvis_say(f"{reachable}/{len(results)} probe(s) reachable.", "ok")
    except Exception as exc:
        jarvis_say(f"Health check failed: {exc}", "error")


def cmd_help(_args: str) -> None:
    jarvis_say("COMMAND REFERENCE", "section")
    commands = [
        ("situation / status / threat",    "Full threat + health intelligence briefing"),
        ("triage / analyze / deep scan",    "Deep AI triage via LangGraph + DeepSeek"),
        ("start / activate / defenses",     "Launch Network Guardian (start_all.py)"),
        ("stop / halt / shutdown",           "Gracefully halt all NG subsystems"),
        ("fleet / devices / nodes",          "Show passive devices + registered probe agents"),
        ("probes / field agents",            "Scan subnet + show all active field probe agents"),
        ("probe health / check probes",      "Ping-check every registered probe's reachability"),
        ("firewall / injection / attacks",   "Query SQL injection history database"),
        ("lateral / movement / pivot",       "Review lateral movement event log"),
        ("metrics / cpu / memory / disk",    "Live OS hardware performance snapshot"),
        ("help / ?",                         "Show this command reference"),
        ("jarvis exit / jarvis shutdown",    "Terminate Jarvis session"),
    ]
    print()
    for cmd, desc in commands:
        print(f"  {C.CYAN}{cmd:<40}{C.RESET}{C.DIM}{desc}{C.RESET}")
    print()
    ds_key = os.environ.get("DEEPSEEK_API_KEY", "")
    status = f"{C.GREEN}ACTIVE{C.RESET}" if ds_key else f"{C.YELLOW}OFFLINE (set DEEPSEEK_API_KEY){C.RESET}"
    jarvis_say(f"DeepSeek AI status: {status}", "info")
    jarvis_say("Natural language accepted — e.g. 'what is the situation of my network?'", "info")


def cmd_exit(_args: str) -> None:
    jarvis_say(f"Shutting down Jarvis. Stay secure, {_OPERATOR}.", "ok")
    print(f"\n{C.DIM}  {SEPARATOR}{C.RESET}\n")
    sys.exit(0)


# ══════════════════════════════════════════════════════════════════
# DISPATCH TABLE
# ══════════════════════════════════════════════════════════════════

DISPATCH: dict[str, Callable] = {
    "cmd_situation":    cmd_situation,
    "cmd_start":        cmd_start,
    "cmd_stop":         cmd_stop,
    "cmd_fleet":        cmd_fleet,
    "cmd_probes":       cmd_probes,
    "cmd_probe_health": cmd_probe_health,
    "cmd_firewall":     cmd_firewall,
    "cmd_lateral":      cmd_lateral,
    "cmd_metrics":      cmd_metrics,
    "cmd_triage":       cmd_triage,
    "cmd_help":         cmd_help,
    "cmd_exit":         cmd_exit,
}


# ══════════════════════════════════════════════════════════════════
# JARVIS CORE CLASS  (programmatic API — wraps the REPL)
# ══════════════════════════════════════════════════════════════════

class JarvisCore:
    """
    Programmatic interface to JARVIS.

    Can be used from code without launching the interactive REPL:

        jarvis = JarvisCore()
        jarvis.dispatch("scan for malware")
        jarvis.dispatch("situation")
    """

    def __init__(
        self,
        voice: bool = False,
        ear: bool = False,
        deepseek_api_key: str = "",
    ) -> None:
        """
        Parameters
        ----------
        voice            : Enable SAPI 5 voice output (Windows only).
        ear              : Enable microphone input (Windows only).
        deepseek_api_key : Override DeepSeek API key (uses env var if not provided).
        """
        if deepseek_api_key:
            os.environ["DEEPSEEK_API_KEY"] = deepseek_api_key

        self._voice: Optional["JarvisVoice"] = None
        self._ear: Optional["JarvisEar"] = None

        if voice and _VOICE_AVAILABLE:
            # Build a silent placeholder on the main thread; the worker thread
            # will reinitialise the real COM backend itself (CoInitialize fix).
            # We defer the startup greeting to avoid COM-on-wrong-thread errors.
            self._voice = JarvisVoice()
        if ear and _EAR_AVAILABLE:
            _mic_idx_str = os.environ.get("JARVIS_MIC_INDEX", "1")
            try:
                _mic_idx: Optional[int] = int(_mic_idx_str)
            except ValueError:
                _mic_idx = None
            _ear_cfg = EarConfig()
            _ear_cfg.input_source = _mic_idx
            _ear_cfg.language     = "en-US"
            self._ear = JarvisEar(cfg=_ear_cfg)

    def dispatch(self, raw: str) -> bool:
        """
        Dispatch a natural-language command.

        Returns True if a handler was invoked, False if unrecognised.
        """
        intent = parse_intent(raw)

        # ── Unrecognised input → conversational reply with live data ─
        if intent is None:
            api_key = os.environ.get("DEEPSEEK_API_KEY", "")
            # Always build live context so JARVIS can answer fact questions
            try:
                context = _build_live_context()
            except Exception:
                context = ""
            reply = _get_chat_reply(raw, _OPERATOR, api_key=api_key, context=context)
            if not reply:
                reply = (
                    f"I wasn't able to classify that request. "
                    f"Try 'help' for a list of what I can do, or ask me about "
                    f"threats, firewall, fleet, metrics, or lateral movement."
                )
            jarvis_say(reply, "info")
            if self._voice:
                self._voice.say(reply)
            return False

        handler = DISPATCH.get(intent)
        if handler:
            handler(raw)
            # ── Speak a natural summary of the result ─────────────
            if self._voice and _CONV_AVAILABLE and intent != "cmd_exit":
                try:
                    snap = _tel().full_snapshot()
                    label, _ = _rep().compute_threat_level()
                    snap["threat_label"] = label
                    extra = {}
                    if intent == "cmd_triage":
                        extra["triage_result"] = _LAST_TRIAGE.copy()
                    spoken = _get_spoken_summary(intent, snap, _OPERATOR, extra)
                    if spoken:
                        self._voice.say(spoken)
                except Exception:
                    pass
            return True
        return False


    def shutdown(self) -> None:
        """Clean up voice/ear resources."""
        if self._voice:
            self._voice.shutdown()
        if self._ear:
            self._ear.stop()


# ══════════════════════════════════════════════════════════════════
# MAIN REPL LOOP
# ══════════════════════════════════════════════════════════════════

def repl() -> None:
    """Interactive Read-Eval-Print Loop."""
    print_banner()
    jarvis_say(f"All systems online, {_OPERATOR}. Type 'help' for commands.", "ok")
    jarvis_say("Monitoring: fleet | firewall | lateral movement | OS metrics", "info")
    if _LG_AVAILABLE and os.environ.get("DEEPSEEK_API_KEY"):
        jarvis_say("DeepSeek AI triage active — try: 'triage scan for threats'", "ai")
    print()

    core = JarvisCore(voice=True, ear=True)

    while True:
        # ── Poll microphone queue (non-blocking) ──────────────────
        if core._ear and core._ear.is_available:
            voice_cmd = core._ear.get_command(timeout=0.0)
            if voice_cmd:
                jarvis_say(f"Voice command received: '{voice_cmd}'", "info")
                raw = voice_cmd
                core.dispatch(raw)
                continue

        try:
            raw = input(f"{C.CYAN}{PROMPT}{C.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            cmd_exit("")

        if not raw:
            continue

        core.dispatch(raw)


if __name__ == "__main__":
    repl()
