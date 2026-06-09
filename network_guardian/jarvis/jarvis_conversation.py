"""
╔══════════════════════════════════════════════════════════════════╗
║     J.A.R.V.I.S  —  Conversational Intelligence Layer           ║
║     jarvis_conversation.py  |  Spoken summaries + Chat           ║
╠══════════════════════════════════════════════════════════════════╣
║  Provides:                                                        ║
║    get_spoken_summary(intent, snap, operator)  → str             ║
║    get_chat_reply(text, operator, api_key)     → str             ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import random
from typing import Any

# ══════════════════════════════════════════════════════════════════
# CANNED FALLBACKS  (used when DeepSeek is offline)
# ══════════════════════════════════════════════════════════════════

_CHAT_FALLBACKS = [
    "I didn't recognise that command. You might try: situation, triage, fleet, "
    "firewall, lateral, or metrics.",
    "That's outside my current operational parameters. I specialise in threat "
    "assessment, fleet monitoring, firewall analysis, and system performance.",
    "Apologies — I couldn't classify that request. Shall I run a full situation "
    "assessment instead?",
    "I'm afraid that falls outside my scope right now. Ask me about your network "
    "threats, devices, or system health.",
    "Noted, but I need a clearer command. Try 'help' for a full list of what I can do.",
]

_GREETING_RESPONSES = [
    "How can I assist you today?",
    "I'm monitoring your network. All systems are active. What would you like to know?",
    "Standing by for your orders.",
    "Online and ready. How may I be of service?",
    "At your service. What shall I look into?",
]

# ══════════════════════════════════════════════════════════════════
# DEEPSEEK SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════════

_JARVIS_SYSTEM_PROMPT = (
    "You are J.A.R.V.I.S. (Just A Rather Very Intelligent System), "
    "the AI assistant for Network Guardian — a professional network security "
    "monitoring platform.\n\n"
    "Personality:\n"
    "- Professional, calm, and precise — like a highly capable British AI assistant\n"
    "- Slightly formal but warm and personable\n"
    "- Address the operator by name when provided\n"
    "- Keep responses concise (2-4 sentences) unless asked to elaborate\n\n"
    "IMPORTANT — You have direct read access to live system telemetry. "
    "When the operator asks a fact-based question about the network, firewall, "
    "fleet, or system metrics, you MUST answer using the data in the context "
    "section below. Do NOT say you lack access — the data is provided to you.\n\n"
    "If the question requires a full table or detailed list, recommend the "
    "specific command name (e.g. 'say firewall for the full log').\n\n"
    "Available commands you can recommend: situation, triage, fleet, firewall, "
    "lateral, metrics, start, stop, help."
)


# ══════════════════════════════════════════════════════════════════
# SPOKEN SUMMARIES  (per-command natural speech)
# ══════════════════════════════════════════════════════════════════

def get_spoken_summary(
    intent:   str,
    snap:     dict[str, Any],
    operator: str | None = None,
    extra:    dict[str, Any] | None = None,
) -> str:
    """
    Return a natural spoken summary string for the given completed command.

    Parameters
    ----------
    intent   : Internal command key, e.g. ``"cmd_situation"``.
    snap     : Full telemetry snapshot (TelemetryAggregator.full_snapshot()).
               Should include ``"threat_label"`` added by the caller.
    operator : Operator name for personalisation (falls back to env var).
    extra    : Optional extra data, e.g. ``{"triage_result": {...}}``.
    """
    op = (operator or os.environ.get("JARVIS_OPERATOR", "sir")).split()[0]
    xd = extra or {}

    _generators: dict[str, Any] = {
        "cmd_situation": _situation_summary,
        "cmd_fleet":     _fleet_summary,
        "cmd_firewall":  _firewall_summary,
        "cmd_lateral":   _lateral_summary,
        "cmd_metrics":   _metrics_summary,
        "cmd_triage":    lambda s, o: _triage_summary(s, o, xd.get("triage_result", {})),
        "cmd_start":     lambda s, o: (
            f"Defenses are now online, {o}. "
            "Network Guardian subsystems are coming up."
        ),
        "cmd_stop":      lambda s, o: (
            f"All defenses have been halted, {o}. "
            "Passive monitoring remains active."
        ),
        "cmd_help":      lambda s, o: (
            f"{o}, the command reference is displayed. "
            "You may speak any command naturally or type it in the prompt."
        ),
    }

    gen = _generators.get(intent)
    if gen is None:
        return ""
    try:
        return gen(snap, op)
    except Exception:
        return f"Command completed, {op}."


# ── Per-command summary builders ───────────────────────────────────

def _situation_summary(snap: dict, op: str) -> str:
    threat  = snap.get("threat_label", "NOMINAL")
    fleet   = snap.get("fleet", [])
    inj     = snap.get("injection", {})
    lat     = snap.get("lateral", [])

    devices = len(fleet) if isinstance(fleet, list) else fleet.get("count", 0)
    blocked = (inj.get("total_fetched", 0) if isinstance(inj, dict) else 0)
    lateral = len(lat) if isinstance(lat, list) else 0

    parts = ["Situation assessment complete."]

    if threat == "NOMINAL":
        parts.append("Threat level is nominal. No active threats detected.")
    elif threat == "ELEVATED":
        parts.append("Threat level is elevated. I recommend reviewing recent activity.")
    elif threat == "HIGH":
        parts.append("Threat level is HIGH. Immediate attention is advised.")
    elif threat == "CRITICAL":
        parts.append("WARNING — threat level is CRITICAL. Immediate action required.")

    if devices:
        parts.append(
            f"{devices} device{'s' if devices != 1 else ''} "
            f"{'are' if devices != 1 else 'is'} registered in your fleet."
        )
    if blocked:
        parts.append(
            f"{blocked} injection attempt{'s' if blocked != 1 else ''} "
            "have been logged."
        )
    if lateral:
        parts.append(
            f"{lateral} lateral movement event{'s' if lateral != 1 else ''} detected."
        )
    if not blocked and not lateral:
        parts.append("No hostile activity detected at this time.")

    return " ".join(parts)


def _fleet_summary(snap: dict, op: str) -> str:
    fleet   = snap.get("fleet", [])
    devices = fleet if isinstance(fleet, list) else fleet.get("devices", [])
    count   = len(devices)
    if count == 0:
        return f"Fleet registry is empty, {op}. No devices currently registered."
    return (
        f"Fleet scan complete. "
        f"{count} device{'s are' if count != 1 else ' is'} "
        "registered in your network."
    )


def _firewall_summary(snap: dict, op: str) -> str:
    inj = snap.get("injection", {})
    if not isinstance(inj, dict):
        return f"Firewall data retrieved, {op}."
    count = inj.get("total_fetched", 0)
    if count == 0:
        return f"No injection records found in the firewall database, {op}."
    records = inj.get("records", []) or []
    blocked = sum(1 for r in records if r.get("blocked"))
    msg = (
        f"Firewall intelligence updated. "
        f"{count} injection record{'s' if count != 1 else ''} retrieved."
    )
    if blocked:
        msg += f" {blocked} confirmed blocked."
    return msg


def _lateral_summary(snap: dict, op: str) -> str:
    lat    = snap.get("lateral", [])
    events = lat if isinstance(lat, list) else lat.get("events", [])
    count  = len(events)
    if count == 0:
        return (
            f"No lateral movement detected, {op}. "
            "Your network perimeter appears secure."
        )
    high = sum(
        1 for e in events
        if str(e.get("severity", "")).upper() in ("HIGH", "CRITICAL")
    )
    msg = (
        f"Lateral movement scan complete. "
        f"{count} event{'s' if count != 1 else ''} detected."
    )
    if high:
        msg += f" {high} require{'s' if high == 1 else ''} immediate attention."
    return msg


def _metrics_summary(snap: dict, op: str) -> str:
    os_m = snap.get("os", {})
    if not isinstance(os_m, dict):
        return f"System metrics retrieved, {op}."

    def _f(v: Any) -> float:
        try:
            return float(str(v).replace("%", "").strip())
        except Exception:
            return 0.0

    cpu  = os_m.get("cpu_percent",  0)
    mem  = os_m.get("mem_percent",  0)
    disk = os_m.get("disk_percent", 0)

    alerts = []
    if _f(cpu)  >= 90: alerts.append("CPU is under heavy load")
    if _f(mem)  >= 90: alerts.append("memory pressure is critical")
    if _f(disk) >= 95: alerts.append("disk space is critically low")

    msg = (
        f"System metrics: CPU at {cpu} percent, "
        f"memory at {mem} percent, disk at {disk} percent."
    )
    if alerts:
        msg += " WARNING: " + "; ".join(alerts) + "."
    else:
        msg += " All resources within acceptable parameters."
    return msg


def _triage_summary(snap: dict, op: str, result: dict) -> str:
    if not result:
        return f"Deep analysis complete, {op}. Review the output for details."
    intent_class = result.get("intent_class", "UNKNOWN")
    confidence   = result.get("confidence", 0.0)
    plan         = result.get("action_plan", []) or []
    recs         = result.get("recommendations", []) or []

    msg = (
        f"Deep analysis complete. "
        f"I've classified this as {intent_class} "
        f"with {int(confidence * 100)} percent confidence."
    )
    if plan:
        n = len(plan)
        msg += f" {n} corrective action{'s are' if n != 1 else ' is'} recommended."
    if recs:
        first = recs[0] if isinstance(recs[0], str) else str(recs[0])
        if len(first) < 130:
            msg += f" Primary recommendation: {first}"
    return msg


# ══════════════════════════════════════════════════════════════════
# CONVERSATIONAL CHAT  (unrecognised inputs + free-form dialogue)
# ══════════════════════════════════════════════════════════════════

def get_chat_reply(
    user_text: str,
    operator:  str | None = None,
    api_key:   str = "",
    context:   str = "",
) -> str:
    """
    Generate a conversational reply for unrecognised free-form input.

    Uses DeepSeek ``deepseek-chat`` if *api_key* is set; otherwise
    returns a contextually appropriate canned response.

    Parameters
    ----------
    user_text : The raw input that the intent parser could not classify.
    operator  : Operator name for personalisation.
    api_key   : DeepSeek API key (optional).
    context   : Brief current system context string (e.g. threat level).
    """
    _op = (operator or os.environ.get("JARVIS_OPERATOR", "sir")).split()[0]

    # Simple greeting detection
    _greet = ("hello", "hi ", "hey", "good morning", "good evening",
              "good afternoon", "how are you", "how's it going")
    if any(user_text.lower().strip().startswith(w) for w in _greet):
        return random.choice(_GREETING_RESPONSES)

    # Try DeepSeek for a genuine response
    if api_key:
        try:
            return _deepseek_chat(user_text, _op, api_key, context)
        except Exception:
            pass

    # Canned fallback
    return random.choice(_CHAT_FALLBACKS)


def _deepseek_chat(
    user_text: str,
    operator:  str,
    api_key:   str,
    context:   str,
) -> str:
    """Synchronous DeepSeek chat call — wraps openai client."""
    from openai import OpenAI

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    system = _JARVIS_SYSTEM_PROMPT
    if operator:
        system += f"\n\nThe operator's name is {operator}."
    if context:
        system += f"\n\nCurrent system context: {context}"

    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user_text},
        ],
        max_tokens=200,
        temperature=0.7,
    )
    return resp.choices[0].message.content.strip()
