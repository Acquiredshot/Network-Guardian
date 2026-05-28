# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — Smart Firewall ReAct Agent

Autonomous agent that actively detects and blocks injection attacks in
real time.  Operates in two complementary modes simultaneously:

  **Event-driven** — subscribes to ``ids.alert`` events on the event bus
  and immediately processes any ``INJECTION``-category alert the IDS fires.

  **Direct scan** — exposes ``scan_payload(payload, source_ip)`` so the
  dashboard, desktop app, and other agents can feed raw payloads directly
  for instant analysis without waiting for the IDS pipeline.

For every detected injection the agent runs a full ReAct cycle:

  OBSERVE  — capture the injection attempt (alert or raw payload)
  REASON   — classify injection type, compute threat score, determine
              escalation tier for the source IP (1st / 2nd / repeat offender)
  ACT      — call ``ips.block_ip()`` to immediately block the attacker,
              publish ``firewall.injection.blocked`` on the event bus,
              optionally generate a PDF incident report
  LEARN    — persist per-IP offense history, update escalation counters,
              adapt future block durations

Escalation tiers
----------------
  Offense 1 → 1-hour block
  Offense 2 → 6-hour block
  Offense 3+ → permanent block

Injection types detected
------------------------
  SQL Injection, XSS, Command Injection, LDAP Injection,
  XXE, SSTI, Path Traversal, HTTP Header (CRLF) Injection
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus
    from network_guardian.ips import IntrusionPreventionSystem

logger = logging.getLogger("network_guardian.agent.smart_firewall")

# ---------------------------------------------------------------------------
# Injection classification
# ---------------------------------------------------------------------------


class InjectionType(Enum):
    SQL            = "sql_injection"
    XSS            = "xss"
    CMD            = "command_injection"
    LDAP           = "ldap_injection"
    XXE            = "xxe"
    SSTI           = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    HEADER         = "header_injection"
    UNKNOWN        = "unknown"


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

@dataclass
class InjectionRule:
    name: str
    pattern: str
    injection_type: InjectionType
    severity: str   # "critical" | "high" | "medium"
    confidence: float  # base confidence contribution 0.0–1.0
    description: str
    _compiled: re.Pattern | None = field(default=None, repr=False)

    @property
    def compiled(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        return self._compiled


_INJECTION_RULES: list[InjectionRule] = [
    # -- SQL Injection -------------------------------------------------------
    InjectionRule(
        name="SQL UNION SELECT",
        pattern=r"union\s+(?:all\s+)?select\b",
        injection_type=InjectionType.SQL, severity="critical", confidence=0.95,
        description="UNION-based SQL injection — attempts to append a secondary SELECT.",
    ),
    InjectionRule(
        name="SQL Tautology",
        pattern=r"(?:'|\")\s*(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
        injection_type=InjectionType.SQL, severity="critical", confidence=0.90,
        description="Tautology SQL injection (e.g. OR 1=1).",
    ),
    InjectionRule(
        name="SQL Stacked Query",
        pattern=r";\s*(?:drop|insert|update|delete|alter|create|exec|execute)\b",
        injection_type=InjectionType.SQL, severity="critical", confidence=0.93,
        description="Stacked query SQL injection — injects a second statement.",
    ),
    InjectionRule(
        name="SQL Blind Time-based",
        pattern=r"(?:sleep\s*\(\s*\d+|waitfor\s+delay\s*'|benchmark\s*\(\s*\d+)",
        injection_type=InjectionType.SQL, severity="high", confidence=0.88,
        description="Blind time-based SQL injection (SLEEP / WAITFOR / BENCHMARK).",
    ),
    InjectionRule(
        name="SQL Comment Stripping",
        pattern=r"(?:--|#|/\*.*?\*/)\s*(?:or|and|select|union|drop)",
        injection_type=InjectionType.SQL, severity="high", confidence=0.80,
        description="SQL comment stripping used to bypass WHERE clauses.",
    ),
    InjectionRule(
        name="SQL Error-based",
        pattern=r"(?:extractvalue|updatexml|floor\s*\(\s*rand|exp\s*\(\s*~)",
        injection_type=InjectionType.SQL, severity="high", confidence=0.85,
        description="Error-based SQL injection via MySQL/MSSQL error leakage.",
    ),
    # -- XSS -----------------------------------------------------------------
    InjectionRule(
        name="XSS Script Tag",
        pattern=r"<\s*script[^>]*>",
        injection_type=InjectionType.XSS, severity="high", confidence=0.95,
        description="Inline <script> tag injection.",
    ),
    InjectionRule(
        name="XSS Event Handler",
        pattern=r"\bon(?:error|load|click|mouse(?:over|out)|key(?:up|down|press)|focus|blur|submit|input|change)\s*=",
        injection_type=InjectionType.XSS, severity="high", confidence=0.92,
        description="Event-handler attribute injection (onerror=, onload=, etc.).",
    ),
    InjectionRule(
        name="XSS javascript: URI",
        pattern=r"javascript\s*:",
        injection_type=InjectionType.XSS, severity="high", confidence=0.90,
        description="javascript: URI used to execute code in href/src attributes.",
    ),
    InjectionRule(
        name="XSS SVG/IMG Payload",
        pattern=r"<\s*(?:svg|img|iframe|object|embed)\s[^>]*(?:on\w+\s*=|src\s*=\s*['\"]javascript)",
        injection_type=InjectionType.XSS, severity="high", confidence=0.87,
        description="XSS via SVG/IMG/IFRAME tag with event handler or javascript: src.",
    ),
    InjectionRule(
        name="XSS HTML Entity Obfuscation",
        pattern=r"&#x?[0-9a-f]{2,5};.*(?:script|on\w+=|javascript)",
        injection_type=InjectionType.XSS, severity="medium", confidence=0.75,
        description="HTML entity-encoded XSS payload attempting obfuscation.",
    ),
    # -- Command Injection ---------------------------------------------------
    InjectionRule(
        name="CMD Pipe/Semicolon",
        pattern=r"(?:[|;`]|\$\()\s*(?:cat|ls|id|whoami|uname|passwd|shadow|wget|curl|nc|bash|sh|cmd|powershell)\b",
        injection_type=InjectionType.CMD, severity="critical", confidence=0.93,
        description="OS command injection via pipe, semicolon, backtick, or $() subshell.",
    ),
    InjectionRule(
        name="CMD Redirection",
        pattern=r"(?:>>?|2>>?)\s*/(?:etc|proc|tmp|dev|var)",
        injection_type=InjectionType.CMD, severity="critical", confidence=0.90,
        description="File redirection targeting sensitive system paths.",
    ),
    InjectionRule(
        name="CMD Double Pipe OR",
        pattern=r"\|\|\s*(?:cat|ls|id|whoami|wget|curl|bash|sh|nc)",
        injection_type=InjectionType.CMD, severity="high", confidence=0.85,
        description="Command injection via shell OR operator (||).",
    ),
    InjectionRule(
        name="CMD URL-encoded Shell",
        pattern=r"%(?:7c|3b|60|26|24%28)\w",
        injection_type=InjectionType.CMD, severity="high", confidence=0.80,
        description="URL-encoded command injection characters (|, ;, `, &, $())",
    ),
    # -- LDAP Injection ------------------------------------------------------
    InjectionRule(
        name="LDAP Filter Escape",
        pattern=r"\)\s*\(\s*(?:cn|uid|mail|objectClass|userPassword)\s*=\s*\*",
        injection_type=InjectionType.LDAP, severity="high", confidence=0.90,
        description="LDAP filter manipulation to enumerate directory entries.",
    ),
    InjectionRule(
        name="LDAP AND/OR Bypass",
        pattern=r"(?:\*\)\(|\|\s*\(|&\s*\(|\)\s*\|)",
        injection_type=InjectionType.LDAP, severity="high", confidence=0.82,
        description="LDAP injection using AND (&) / OR (|) operator abuse.",
    ),
    # -- XXE -----------------------------------------------------------------
    InjectionRule(
        name="XXE ENTITY Declaration",
        pattern=r"<!(?:ENTITY|DOCTYPE)[^>]+(?:SYSTEM|PUBLIC)\s+['\"](?:file|http|ftp|php|expect)://",
        injection_type=InjectionType.XXE, severity="critical", confidence=0.95,
        description="XML External Entity (XXE) — SYSTEM/PUBLIC entity referencing external resource.",
    ),
    InjectionRule(
        name="XXE Parameter Entity",
        pattern=r"<!ENTITY\s+%\s+\w+\s+SYSTEM",
        injection_type=InjectionType.XXE, severity="critical", confidence=0.92,
        description="XXE via parameter entity — often used for blind XXE exfiltration.",
    ),
    # -- SSTI ----------------------------------------------------------------
    InjectionRule(
        name="SSTI Jinja2/Twig",
        pattern=r"\{\{[^}]+\}\}",
        injection_type=InjectionType.SSTI, severity="critical", confidence=0.85,
        description="Server-Side Template Injection — Jinja2/Twig {{ }} expression.",
    ),
    InjectionRule(
        name="SSTI FreeMarker/Spring EL",
        pattern=r"\$\{[^}]+\}",
        injection_type=InjectionType.SSTI, severity="critical", confidence=0.80,
        description="SSTI — FreeMarker/Spring EL ${} expression.",
    ),
    InjectionRule(
        name="SSTI ERB/Ruby",
        pattern=r"<%=\s*[^%]+\s*%>",
        injection_type=InjectionType.SSTI, severity="critical", confidence=0.85,
        description="SSTI — ERB/Ruby <%= %> expression.",
    ),
    InjectionRule(
        name="SSTI Thymeleaf",
        pattern=r"#\{[^}]+\}",
        injection_type=InjectionType.SSTI, severity="high", confidence=0.78,
        description="SSTI — Thymeleaf #{} expression.",
    ),
    # -- Path Traversal ------------------------------------------------------
    InjectionRule(
        name="Path Traversal Sequence",
        pattern=r"(?:\.\.[\\/]){2,}",
        injection_type=InjectionType.PATH_TRAVERSAL, severity="high", confidence=0.90,
        description="Directory traversal sequence (../../) to escape the web root.",
    ),
    InjectionRule(
        name="Path Traversal URL-encoded",
        pattern=r"(?:%2e%2e%2f|%2e%2e/|\.\.%2f|%2e\.%2f){2,}",
        injection_type=InjectionType.PATH_TRAVERSAL, severity="high", confidence=0.88,
        description="URL-encoded path traversal (%2e%2e%2f).",
    ),
    InjectionRule(
        name="Path Traversal Double-encoded",
        pattern=r"(?:%252e%252e%252f|%252e%252e/){2,}",
        injection_type=InjectionType.PATH_TRAVERSAL, severity="high", confidence=0.85,
        description="Double URL-encoded path traversal to bypass decoding filters.",
    ),
    InjectionRule(
        name="Path Traversal Null Byte",
        pattern=r"(?:\.\.[\\/].*%00|%00.*\.\.[\\/])",
        injection_type=InjectionType.PATH_TRAVERSAL, severity="high", confidence=0.82,
        description="Null-byte path traversal to truncate file extension checks.",
    ),
    # -- HTTP Header Injection (CRLF) ----------------------------------------
    InjectionRule(
        name="CRLF Header Injection",
        pattern=r"(?:%0d%0a|%0a%0d|\r\n|\n\r)(?:\w[\w-]+\s*:)",
        injection_type=InjectionType.HEADER, severity="high", confidence=0.92,
        description="CRLF injection to inject arbitrary HTTP response headers.",
    ),
    InjectionRule(
        name="Header Newline Split",
        pattern=r"(?:%0a|%0d)(?:Set-Cookie|Location|Content-Type|X-|HTTP/)",
        injection_type=InjectionType.HEADER, severity="high", confidence=0.88,
        description="HTTP response splitting via injected newline characters.",
    ),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

_SEVERITY_SCORES = {"critical": 40, "high": 20, "medium": 10}


@dataclass
class InjectionDetection:
    """A single injection hit from a payload scan."""

    detection_id: str
    source_ip: str
    payload_snippet: str   # first 300 chars of matched payload
    injection_type: InjectionType
    rule_name: str
    severity: str
    confidence: float
    timestamp: str = ""
    action_taken: str = ""    # "blocked" | "escalated" | "rate_limited" | "logged"
    block_duration: int | None = None  # seconds; None = permanent

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["injection_type"] = self.injection_type.value
        return d


@dataclass
class ReActStep:
    phase: str
    thought: str
    detail: Any = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SmartFirewallReport:
    """Cycle summary produced by SmartFirewallAgent.run_cycle()."""

    report_id: str
    generated_at: str
    cycle: int
    risk_level: str          # "low" | "medium" | "high" | "critical"
    threat_score: float      # 0–100
    payloads_scanned: int
    injections_detected: int
    ips_blocked: list[str]
    react_steps: list[dict]
    threats: list[dict]
    actions: list[dict]
    recommendations: list[str]
    pdf_path: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class SmartFirewallAgent:
    """Autonomous injection-detection and active-blocking ReAct agent.

    Parameters
    ----------
    ips:
        The live ``IntrusionPreventionSystem`` instance. Required for
        autonomous blocking; pass ``None`` to run in detection-only mode.
    event_bus:
        The Network Guardian ``EventBus``. Used to subscribe to IDS alerts
        and to publish ``firewall.injection.blocked`` events.
    auto_block:
        When ``True`` (default) the agent automatically calls
        ``ips.block_ip()`` for every confirmed injection detection.
        Set to ``False`` for detection-only / alert mode.
    generate_pdf:
        ``"on_threat"`` (default) | ``"always"`` | ``"never"``
    interval_secs:
        How often the autonomous loop wakes to process queued detections
        (default 5 seconds).  Event-driven blocking is immediate regardless.
    data_dir:
        Persistence directory (default ``~/.network_guardian/smart_firewall/``).
    allowlist:
        IPs that should never be blocked (e.g. internal monitoring hosts).
    """

    # Escalation tiers: offense_count → block duration in seconds (None = permanent)
    _ESCALATION: list[int | None] = [3600, 21600, None]

    def __init__(
        self,
        ips: "IntrusionPreventionSystem | None" = None,
        event_bus: "EventBus | None" = None,
        auto_block: bool = True,
        generate_pdf: str = "on_threat",
        interval_secs: float = 5.0,
        data_dir: Path | None = None,
        allowlist: list[str] | None = None,
    ) -> None:
        self._ips = ips
        self._event_bus = event_bus
        self.auto_block = auto_block
        self.generate_pdf = generate_pdf
        self.interval_secs = interval_secs

        self._data_dir = data_dir or (Path.home() / ".network_guardian" / "smart_firewall")
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._history_path = self._data_dir / "injection_history.json"

        self._allowlist: set[str] = set(allowlist or [])
        self._allowlist.update({"127.0.0.1", "::1"})

        # Per-IP offense history:  ip → list of detection dicts
        self._ip_history: dict[str, list[dict]] = self._load_history()

        # Pending detections fed by the event-bus subscription
        self._pending: asyncio.Queue[InjectionDetection] = asyncio.Queue()

        self._running = False
        self._task: asyncio.Task | None = None
        self._cycle = 0
        self._last_report: SmartFirewallReport | None = None

        # Subscribe to IDS alerts from the event bus
        if self._event_bus:
            self._event_bus.subscribe("ids.alert", self._on_ids_alert)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan_payload(
        self,
        payload: str,
        source_ip: str = "unknown",
        destination_ip: str = "",
        destination_port: int = 0,
    ) -> list[InjectionDetection]:
        """Immediately scan *payload* for all injection types.

        Returns a list of detections (may be empty).  If ``auto_block`` is
        enabled the source IP is blocked for each critical/high hit.

        This is the primary integration point for the desktop app and
        any HTTP middleware that wants real-time request inspection.
        """
        detections = self._detect(payload, source_ip)
        for d in detections:
            await self._act_on_detection(d)
        return detections

    async def run_cycle(self) -> SmartFirewallReport:
        """Execute one full Observe → Reason → Act → Learn cycle.

        Drains the pending queue built from event-bus ``ids.alert``
        subscriptions.  Also runs a self-test payload if the queue is
        empty to confirm rules are active.
        """
        self._cycle += 1
        cycle = self._cycle
        report_id = uuid.uuid4().hex[:12]
        steps: list[ReActStep] = []
        all_detections: list[InjectionDetection] = []
        blocked_ips: list[str] = []
        actions: list[dict] = []
        recommendations: list[str] = []

        def _step(phase: str, thought: str, detail: Any = None) -> None:
            s = ReActStep(phase=phase, thought=thought, detail=detail)
            steps.append(s)
            logger.info("[SFIREWALL][%s] %s", phase.upper(), thought)

        # ---- OBSERVE ------------------------------------------------
        _step("observe", f"Smart Firewall cycle #{cycle} — draining injection queue")
        queued: list[InjectionDetection] = []
        while not self._pending.empty():
            try:
                queued.append(self._pending.get_nowait())
            except asyncio.QueueEmpty:
                break

        _step("observe",
              f"Collected {len(queued)} queued detection(s) from event bus",
              {"queued": len(queued)})

        # ---- REASON -------------------------------------------------
        _step("reason", "Classifying each injection, computing escalation tier per source IP")
        threat_score = 0.0
        threats: list[dict] = []

        for det in queued:
            all_detections.append(det)
            score = _SEVERITY_SCORES.get(det.severity, 10)
            offense_n = len(self._ip_history.get(det.source_ip, []))
            # Escalation bonus
            if offense_n >= 2:
                score = min(score * 1.5, 40)
            threat_score += score

            escalation_label = (
                "first offense" if offense_n == 0 else
                "second offense" if offense_n == 1 else
                f"repeat offender (#{offense_n + 1})"
            )
            block_dur = self._block_duration(det.source_ip)

            _step("reason",
                  f"{det.injection_type.value} from {det.source_ip} — "
                  f"severity={det.severity}, confidence={det.confidence:.0%}, "
                  f"{escalation_label} → block={'permanent' if block_dur is None else f'{block_dur}s'}",
                  {"ip": det.source_ip, "type": det.injection_type.value, "score": score})

            threats.append({
                "title":           f"{det.injection_type.value.replace('_', ' ').title()} from {det.source_ip}",
                "severity":        det.severity,
                "category":        "injection",
                "injection_type":  det.injection_type.value,
                "rule":            det.rule_name,
                "source_ip":       det.source_ip,
                "confidence":      det.confidence,
                "escalation":      escalation_label,
                "payload_snippet": det.payload_snippet,
                "timestamp":       det.timestamp,
                "action_taken":    det.action_taken,
                "resolved":        det.action_taken == "blocked",
            })

        threat_score = min(100.0, threat_score)
        if threat_score == 0:
            risk_level = "low"
        elif threat_score < 30:
            risk_level = "medium"
        elif threat_score < 60:
            risk_level = "high"
        else:
            risk_level = "critical"

        _step("reason",
              f"Risk: {risk_level.upper()} ({threat_score:.0f}/100) across "
              f"{len(threats)} injection(s) from "
              f"{len({d.source_ip for d in all_detections})} unique IP(s)")

        # ---- ACT ----------------------------------------------------
        if threats:
            _step("act", f"Executing active response for {len(threats)} injection(s)")
            for det in queued:
                result = await self._act_on_detection(det)
                if result:
                    blocked_ips.append(det.source_ip)
                    actions.append({
                        "action":  f"Blocked {det.source_ip}",
                        "detail":  f"{det.injection_type.value}: {det.rule_name}",
                        "success": True,
                    })
                    _step("act", f"Blocked {det.source_ip} — {det.injection_type.value}")
                else:
                    actions.append({
                        "action":  f"Logged {det.source_ip}",
                        "detail":  f"Auto-block disabled or IP allowlisted",
                        "success": True,
                    })

            if self._event_bus:
                await self._event_bus.publish({
                    "topic": "firewall.injection.cycle",
                    "data": {
                        "cycle": cycle,
                        "risk_level": risk_level,
                        "threat_score": threat_score,
                        "ips_blocked": list(set(blocked_ips)),
                        "injections": len(threats),
                    },
                })
        else:
            _step("act", "No injections in this cycle — no action required")

        # Build recommendations
        types_seen = {d.injection_type for d in all_detections}
        for inj_type in types_seen:
            recommendations.append(_recommendation(inj_type))
        if risk_level in ("high", "critical"):
            recommendations.append(
                "Review application WAF rules and input validation immediately."
            )
            recommendations.append(
                "Audit all blocked IPs in the IPS and review access logs."
            )
        if not threats:
            recommendations.append(
                "No injections detected. Maintain strict input validation and output encoding."
            )

        # ---- LEARN --------------------------------------------------
        _step("learn", f"Persisting {len(all_detections)} detection(s) to history")
        self._save_detections_to_history(all_detections)

        # ---- PDF ----------------------------------------------------
        pdf_path: str | None = None
        should_pdf = (
            (self.generate_pdf == "on_threat" and threats) or
            self.generate_pdf == "always"
        )

        report = SmartFirewallReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            cycle=cycle,
            risk_level=risk_level,
            threat_score=threat_score,
            payloads_scanned=len(queued),
            injections_detected=len(all_detections),
            ips_blocked=list(set(blocked_ips)),
            react_steps=[s.to_dict() for s in steps],
            threats=threats,
            actions=actions,
            recommendations=recommendations,
        )

        if should_pdf:
            _step("act", "Generating PDF incident report")
            try:
                from network_guardian.agent.pdf_reporter import build_report_pdf
                obs = {"host": "smart_firewall", "cycle": cycle}
                pdf = await asyncio.to_thread(
                    build_report_pdf,
                    "smart_firewall",
                    report_id,
                    f"SmartFirewallAgent (cycle #{cycle})",
                    risk_level,
                    threat_score,
                    report.react_steps,
                    threats,
                    actions,
                    recommendations,
                    obs,
                )
                pdf_path = str(pdf)
                _step("learn", f"PDF saved: {pdf_path}")
                logger.info("[SmartFirewall] PDF written: %s", pdf_path)
            except Exception as exc:
                logger.error("PDF generation failed: %s", exc)

        report.pdf_path = pdf_path
        self._last_report = report
        return report

    def start(self) -> None:
        """Schedule the autonomous loop on the running event loop."""
        if self._running:
            logger.warning("SmartFirewallAgent already running")
            return
        self._running = True
        self._task = asyncio.ensure_future(self._loop())
        logger.info(
            "SmartFirewallAgent started — auto_block=%s interval=%.0fs",
            self.auto_block, self.interval_secs,
        )

    def stop(self) -> None:
        """Cancel the autonomous loop."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("SmartFirewallAgent stopped")

    async def run(self) -> None:
        """Blocking async loop — awaitable entry point for standalone use."""
        self.start()
        if self._task:
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def last_report(self) -> SmartFirewallReport | None:
        return self._last_report

    def offense_count(self, ip: str) -> int:
        """Number of confirmed injection offenses recorded for *ip*."""
        return len(self._ip_history.get(ip, []))

    def clear_history(self, ip: str | None = None) -> None:
        """Remove offense history for one IP or all IPs."""
        if ip:
            self._ip_history.pop(ip, None)
        else:
            self._ip_history.clear()
        self._persist_history()

    # ------------------------------------------------------------------
    # Internal: detection
    # ------------------------------------------------------------------

    def _detect(self, payload: str, source_ip: str) -> list[InjectionDetection]:
        """Run all injection rules against *payload*. Returns detections."""
        detections: list[InjectionDetection] = []
        seen_types: set[InjectionType] = set()

        for rule in _INJECTION_RULES:
            if rule.compiled.search(payload):
                # Deduplicate: one detection per injection type per payload
                if rule.injection_type in seen_types:
                    continue
                seen_types.add(rule.injection_type)
                detections.append(InjectionDetection(
                    detection_id=uuid.uuid4().hex[:10],
                    source_ip=source_ip,
                    payload_snippet=payload[:300],
                    injection_type=rule.injection_type,
                    rule_name=rule.name,
                    severity=rule.severity,
                    confidence=rule.confidence,
                ))
                logger.warning(
                    "[SmartFirewall] %s detected from %s — rule='%s' severity=%s",
                    rule.injection_type.value, source_ip, rule.name, rule.severity,
                )
        return detections

    # ------------------------------------------------------------------
    # Internal: response
    # ------------------------------------------------------------------

    async def _act_on_detection(self, det: InjectionDetection) -> bool:
        """Applies IPS block for *det*. Returns True if blocked."""
        if det.source_ip in self._allowlist:
            det.action_taken = "allowlisted"
            return False

        if not self.auto_block or self._ips is None:
            det.action_taken = "logged"
            await self._publish_detection_event(det)
            return False

        # Check already blocked
        if self._ips.is_blocked(det.source_ip):
            det.action_taken = "already_blocked"
            return False

        duration = self._block_duration(det.source_ip)
        from network_guardian.ips import BlockReason
        from network_guardian.models.network import Severity as Sev

        sev_map = {"critical": Sev.CRITICAL, "high": Sev.HIGH, "medium": Sev.MEDIUM}
        sev = sev_map.get(det.severity, Sev.HIGH)

        await self._ips.block_ip(
            ip=det.source_ip,
            reason=BlockReason.AUTO_IDS,
            severity=sev,
            duration=duration,
            alert_id=det.detection_id,
            description=(
                f"SmartFirewall auto-block: {det.injection_type.value} "
                f"— {det.rule_name} (confidence={det.confidence:.0%})"
            ),
        )

        det.action_taken = "blocked"
        det.block_duration = duration

        offense = self.offense_count(det.source_ip)  # before saving
        logger.warning(
            "[SmartFirewall] BLOCKED %s — %s offense #%d, duration=%s",
            det.source_ip, det.injection_type.value, offense + 1,
            "permanent" if duration is None else f"{duration}s",
        )

        await self._publish_detection_event(det)
        return True

    async def _publish_detection_event(self, det: InjectionDetection) -> None:
        if self._event_bus is None:
            return
        try:
            from network_guardian.core.events import Event
            await self._event_bus.publish(Event(
                topic="firewall.injection.blocked",
                data=det.to_dict(),
            ))
        except Exception as exc:
            logger.debug("Event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Internal: event bus callback
    # ------------------------------------------------------------------

    async def _on_ids_alert(self, event: Any) -> None:
        """Called by the event bus when the IDS fires an alert."""
        try:
            alert = event.data.get("alert", {})
            category = alert.get("category", "")
            if category != "injection":
                return

            payload = alert.get("raw_data", "") or alert.get("description", "")
            source_ip = alert.get("source_ip", "unknown")

            if not payload:
                return

            detections = self._detect(payload, source_ip)
            for d in detections:
                await self._pending.put(d)

        except Exception as exc:
            logger.debug("SmartFirewallAgent._on_ids_alert error: %s", exc)

    # ------------------------------------------------------------------
    # Internal: autonomous loop
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_cycle()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("SmartFirewallAgent loop error: %s", exc)
            await asyncio.sleep(self.interval_secs)

    # ------------------------------------------------------------------
    # Internal: escalation
    # ------------------------------------------------------------------

    def _block_duration(self, ip: str) -> int | None:
        """Return the appropriate block duration for *ip* based on offense count."""
        offense_count = len(self._ip_history.get(ip, []))
        idx = min(offense_count, len(self._ESCALATION) - 1)
        return self._ESCALATION[idx]

    # ------------------------------------------------------------------
    # Internal: persistence
    # ------------------------------------------------------------------

    def _load_history(self) -> dict[str, list[dict]]:
        if self._history_path.exists():
            try:
                return json.loads(self._history_path.read_text())
            except Exception:
                pass
        return {}

    def _persist_history(self) -> None:
        try:
            self._history_path.write_text(
                json.dumps(self._ip_history, indent=2, default=str)
            )
        except Exception as exc:
            logger.error("SmartFirewallAgent: failed to persist history: %s", exc)

    def _save_detections_to_history(self, detections: list[InjectionDetection]) -> None:
        for det in detections:
            if det.source_ip not in self._ip_history:
                self._ip_history[det.source_ip] = []
            self._ip_history[det.source_ip].append(det.to_dict())
            # Cap history per IP at 500 entries
            if len(self._ip_history[det.source_ip]) > 500:
                self._ip_history[det.source_ip] = (
                    self._ip_history[det.source_ip][-500:]
                )
        if detections:
            self._persist_history()


# ---------------------------------------------------------------------------
# Recommendation catalogue
# ---------------------------------------------------------------------------

def _recommendation(inj_type: InjectionType) -> str:
    return {
        InjectionType.SQL: (
            "Use parameterised queries / prepared statements for all DB operations. "
            "Never interpolate user input into SQL strings."
        ),
        InjectionType.XSS: (
            "Apply context-aware output encoding (HTML, JS, URL) and a strict "
            "Content-Security-Policy (CSP) header."
        ),
        InjectionType.CMD: (
            "Avoid shell=True in subprocess calls. Use allowlists for any "
            "user-controlled arguments and strip shell metacharacters."
        ),
        InjectionType.LDAP: (
            "Use an LDAP library that supports parameterised filters. "
            "Escape all special characters (*, (, ), \\, NUL) in user input."
        ),
        InjectionType.XXE: (
            "Disable external entity processing in your XML parser "
            "(FEATURE_EXTERNAL_GENERAL_ENTITIES=False)."
        ),
        InjectionType.SSTI: (
            "Never pass unsanitised user input to template render() calls. "
            "Use a sandbox environment or restrict the template context."
        ),
        InjectionType.PATH_TRAVERSAL: (
            "Resolve and validate all file paths against the intended root directory "
            "using os.path.realpath / Path.resolve() before opening files."
        ),
        InjectionType.HEADER: (
            "Strip \\r and \\n from all header values before forwarding or "
            "rendering HTTP responses."
        ),
        InjectionType.UNKNOWN: (
            "Investigate the flagged payload manually and harden the relevant "
            "input handling code."
        ),
    }.get(inj_type, "Review the flagged input handling path for this injection type.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _cli_main() -> None:
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    print("Network Guardian — Smart Firewall Agent")
    print("Detection-only mode (no live IPS in CLI). Type a payload to scan.")
    print("Commands: quit, history <ip>, clear <ip>, help\n")

    agent = SmartFirewallAgent(ips=None, event_bus=None, auto_block=False)

    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("payload> ").strip()
            )
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not line:
            continue

        cmd, _, rest = line.partition(" ")
        cmd = cmd.lower()

        if cmd == "quit":
            break
        elif cmd == "history":
            ip = rest.strip()
            history = agent._ip_history.get(ip, [])
            if history:
                for h in history[-5:]:
                    print(f"  {h.get('timestamp','')} — {h.get('injection_type','')} "
                          f"— {h.get('rule_name','')} [{h.get('severity','')}]")
            else:
                print(f"  No history for {ip!r}")
        elif cmd == "clear":
            ip = rest.strip() or None
            agent.clear_history(ip)
            print(f"  Cleared {'all' if ip is None else ip}")
        elif cmd == "help":
            print("  <payload>      Scan a raw payload string")
            print("  history <ip>   Show last 5 detections for an IP")
            print("  clear [<ip>]   Clear history for one or all IPs")
            print("  quit           Exit")
        else:
            # Treat the whole line as a payload
            src = input("source IP (blank=unknown)> ").strip() or "unknown"
            detections = await agent.scan_payload(line, source_ip=src)
            if detections:
                for d in detections:
                    print(f"  [{d.severity.upper()}] {d.injection_type.value} — "
                          f"{d.rule_name} (conf={d.confidence:.0%})")
            else:
                print("  No injections detected.")


if __name__ == "__main__":
    asyncio.run(_cli_main())
