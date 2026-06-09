# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — Triage Agent (Orchestration Central Brain)

Master coordinator that parses multimodal user intent, maintains live system
state across all sub-agents, and delegates complex goals to the right agents.

Architecture
-----------
  OBSERVE  — ingest intent (text command, event trigger, or structured goal)
             and snapshot current system state across all active agents
  REASON   — classify intent into one of eight intent classes, score confidence,
             select the optimal set of sub-agents, build an ordered execution plan
  ACT      — dispatch GoalTasks concurrently or sequentially to sub-agents,
             collect and merge results, compute aggregate threat level
  LEARN    — update SystemState from results, publish outcome events,
             persist task history for audit trail

Intent classes
--------------
  THREAT_RESPONSE  — block / quarantine / kill an active threat
  THREAT_HUNT      — scan / investigate / detect threats proactively
  NETWORK_OPS      — probe / map / discover the network topology
  SYSTEM_AUDIT     — audit / assess / generate compliance reports
  CLOAKING_OPS     — activate / configure IP or WiFi cloaking
  REPORT_GEN       — summarize status / generate PDF reports
  AGENT_CTRL       — start / stop / reconfigure individual agents
  STATUS_QUERY     — query live system state, threat level, or agent health

Event bus interface
-------------------
  Subscribes:
    ``triage.command``             — free-text or structured goal injection
    ``ids.alert``                  — IDS alerts update active threat list
    ``firewall.injection.blocked`` — blocked-IP events update blocked_ips set
    ``monitor.anomaly``            — anomaly events escalate threat level
    ``probe.discovery.open_port``  — port discoveries update system state
    ``probe.discovery.rogue_ap``   — rogue AP discoveries escalate threat level
    ``probe.discovery.weak_auth``  — weak-auth discoveries update state

  Publishes:
    ``triage.plan``      — execution plan for an accepted goal
    ``triage.delegated`` — sub-task handed to a specific agent
    ``triage.completed`` — goal fully resolved with outcome
    ``triage.status``    — periodic system state broadcast (every 60 s)
    ``triage.error``     — goal failed or could not be classified
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event

if TYPE_CHECKING:
    from network_guardian.core.engine import Engine
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.triage")

# ---------------------------------------------------------------------------
# LangGraph + DeepSeek reasoner — optional; activated when DEEPSEEK_API_KEY
# is set or explicitly passed to TriageAgent.triage().
# ---------------------------------------------------------------------------

try:
    from network_guardian.ai.langgraph_reasoner import reason_about_intent as _lg_reason
    _LANGGRAPH_AVAILABLE = True
except ImportError:  # langgraph not installed
    _LANGGRAPH_AVAILABLE = False
    _lg_reason = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Intent classification
# ---------------------------------------------------------------------------

class IntentClass(str, Enum):
    THREAT_RESPONSE = "THREAT_RESPONSE"
    THREAT_HUNT     = "THREAT_HUNT"
    NETWORK_OPS     = "NETWORK_OPS"
    SYSTEM_AUDIT    = "SYSTEM_AUDIT"
    CLOAKING_OPS    = "CLOAKING_OPS"
    REPORT_GEN      = "REPORT_GEN"
    AGENT_CTRL      = "AGENT_CTRL"
    STATUS_QUERY    = "STATUS_QUERY"
    UNKNOWN         = "UNKNOWN"


# Phrase matches score 2; single-word matches score 1.
_INTENT_KEYWORDS: dict[IntentClass, list[str]] = {
    IntentClass.THREAT_RESPONSE: [
        "block", "ban", "quarantine", "kill process", "terminate", "stop attack",
        "isolate", "contain", "neutralize", "eradicate", "respond", "mitigate",
    ],
    IntentClass.THREAT_HUNT: [
        "scan", "check", "investigate", "hunt", "find", "detect",
        "search", "analyze", "inspect", "look for", "discover threat",
        "is there malware", "malware scan", "ransomware check", "suspicious",
    ],
    IntentClass.NETWORK_OPS: [
        "probe", "map network", "topology", "ping", "traceroute",
        "network scan", "arp scan", "discover hosts", "open ports", "port scan",
    ],
    IntentClass.SYSTEM_AUDIT: [
        "audit", "assess", "security review", "compliance", "vulnerability scan",
        "harden", "patch", "baseline", "risk assessment", "security posture",
    ],
    IntentClass.CLOAKING_OPS: [
        "cloak", "hide", "stealth", "mask", "anonymous", "privacy mode",
        "ip cloak", "wifi stealth", "obfuscate", "conceal", "vpn",
    ],
    IntentClass.REPORT_GEN: [
        "report", "summary", "summarize", "generate report", "export pdf",
        "incident report", "pdf", "document findings", "create report",
    ],
    IntentClass.AGENT_CTRL: [
        "start agent", "stop agent", "enable agent", "disable agent",
        "restart agent", "configure agent", "turn on agent", "turn off agent",
    ],
    IntentClass.STATUS_QUERY: [
        "status", "health check", "threat level", "what is running", "show agents",
        "active threats", "running agents", "overview", "how many threats",
        "dashboard", "system state", "are there",
    ],
}


def _classify_intent(text: str) -> tuple[IntentClass, float]:
    """Keyword-score text against intent classes; return best match + confidence."""
    text_lower = text.lower()
    scores: dict[IntentClass, int] = {cls: 0 for cls in IntentClass}

    for cls, keywords in _INTENT_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                scores[cls] += 2 if " " in kw else 1  # phrase match weighs more

    best = max(scores, key=lambda c: scores[c])
    total = sum(scores.values()) or 1
    confidence = min(scores[best] / total, 1.0)
    return (best if scores[best] > 0 else IntentClass.UNKNOWN, confidence)


def _extract_agent_name(text: str) -> str:
    """Best-effort extraction of a named agent from free text."""
    mapping = {
        "smart firewall": "smart_firewall",
        "firewall": "smart_firewall",
        "web browsing": "web_browsing",
        "web browser": "web_browsing",
        "malware": "malware_scanner",
        "ransomware": "ransomware_monitor",
        "email": "email_scanner",
        "cloaking": "cloaking",
        "ids": "ids",
        "ips": "ips",
        "probe": "network_probe",
        "auditor": "auditor",
    }
    for phrase, name in mapping.items():
        if phrase in text:
            return name
    return "unknown"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class GoalStep:
    """A single dispatched step within an execution plan."""
    step_id: str
    agent: str          # logical agent key (e.g. "smart_firewall", "malware_scanner")
    action: str         # human-readable description of what the step does
    kwargs: dict        # arguments forwarded to the dispatch handler
    depends_on: list[str] = field(default_factory=list)
    status: str = "pending"    # pending | running | done | failed
    result: Any = None
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "agent": self.agent,
            "action": self.action,
            "status": self.status,
            "error": self.error,
        }


@dataclass
class GoalTask:
    """A user goal decomposed into ordered GoalSteps."""
    task_id: str
    intent: str
    intent_class: IntentClass
    confidence: float
    created_at: str
    steps: list[GoalStep]
    status: str = "pending"    # pending | running | completed | failed
    react_steps: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "intent": self.intent,
            "intent_class": self.intent_class.value,
            "confidence": round(self.confidence, 3),
            "created_at": self.created_at,
            "status": self.status,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class SystemState:
    """Live snapshot of system-wide security posture, maintained by TriageAgent."""
    threat_level: str = "green"    # green | yellow | orange | red
    active_threats: list[dict] = field(default_factory=list)
    blocked_ips: set = field(default_factory=set)
    agent_statuses: dict[str, str] = field(default_factory=dict)
    recent_events: deque = field(default_factory=lambda: deque(maxlen=200))
    ongoing_tasks: dict[str, GoalTask] = field(default_factory=dict)
    threat_counts: dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    last_updated: str = ""

    def to_dict(self) -> dict:
        return {
            "threat_level": self.threat_level,
            "active_threats": self.active_threats[-20:],
            "blocked_ips_count": len(self.blocked_ips),
            "agent_statuses": self.agent_statuses,
            "threat_counts": self.threat_counts,
            "ongoing_tasks_count": len(self.ongoing_tasks),
            "last_updated": self.last_updated,
        }


@dataclass
class TriageResult:
    """Full outcome record produced by one triage() invocation."""
    task_id: str
    intent: str
    intent_class: str
    confidence: float
    plan: list[dict]
    outcome: str           # success | partial | failed | classified_only
    actions_taken: list[str]
    findings: list[dict]
    recommendations: list[str]
    duration_ms: float
    system_state_snapshot: dict
    react_steps: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Triage Agent
# ---------------------------------------------------------------------------

class TriageAgent:
    """Orchestration Central Brain — master coordinator for all sub-agents.

    Parses multimodal user intent (text commands, event-bus triggers, and
    structured goal dicts), maintains live SystemState by observing the event
    bus, and delegates complex goals to sub-agents via the Engine's lazy
    subsystems.
    """

    _THREAT_LEVELS = ("green", "yellow", "orange", "red")

    def __init__(self, engine: "Engine") -> None:
        self.engine = engine
        self._bus: "EventBus" = engine.event_bus
        self._state = SystemState()
        self._history: list[dict] = []      # ring buffer of completed task records
        self._running = False
        self._status_task: asyncio.Task | None = None

        # Optional agents not in engine — instantiated lazily on first use
        self._malware_agent = None
        self._ransomware_agent = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Subscribe to event bus and begin periodic state broadcasts."""
        if self._running:
            return
        self._running = True

        self._bus.subscribe("triage.command",              self._on_triage_command)
        self._bus.subscribe("ids.alert",                   self._on_ids_alert)
        self._bus.subscribe("firewall.injection.blocked",  self._on_firewall_event)
        self._bus.subscribe("monitor.anomaly",             self._on_anomaly)
        self._bus.subscribe("probe.discovery.open_port",   self._on_probe_event)
        self._bus.subscribe("probe.discovery.rogue_ap",    self._on_probe_event)
        self._bus.subscribe("probe.discovery.weak_auth",   self._on_probe_event)

        try:
            loop = asyncio.get_running_loop()
            self._status_task = loop.create_task(self._status_broadcast_loop())
        except RuntimeError:
            pass  # No running loop yet; broadcasts will begin when the loop starts.

        self._state.agent_statuses["triage"] = "running"
        logger.info("TriageAgent started — Orchestration Central Brain online")

    async def stop(self) -> None:
        """Unsubscribe from the event bus and cancel background tasks."""
        self._running = False
        if self._status_task and not self._status_task.done():
            self._status_task.cancel()
            try:
                await self._status_task
            except asyncio.CancelledError:
                pass
        self._state.agent_statuses["triage"] = "stopped"
        logger.info("TriageAgent stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Primary public API
    # ------------------------------------------------------------------

    async def triage(
        self,
        intent: str,
        context: dict | None = None,
    ) -> TriageResult:
        """Parse *intent* text and orchestrate sub-agents to satisfy the goal.

        Supports three input modalities:
          1. Free-text natural language commands (e.g. "scan for malware")
          2. Structured goal dicts passed via *context* (e.g. ``{"target_ip": "10.0.0.5"}``)
          3. Event-bus triggers routed through ``_on_triage_command``

        Returns a ``TriageResult`` containing the execution plan, delegated
        actions, findings, and recommendations.
        """
        start_ts = time.monotonic()
        context = context or {}
        task_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        react_steps: list[dict] = []

        def _step(phase: str, thought: str, detail: Any = None) -> None:
            entry = {
                "phase": phase,
                "thought": thought,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            react_steps.append(entry)
            logger.info("[TRIAGE][%s] %s", phase.upper(), thought)

        # ── OBSERVE ──────────────────────────────────────────────────────
        _step("OBSERVE", f"Intent received: {intent!r}", {
            "context_keys": list(context.keys()),
            "current_threat_level": self._state.threat_level,
            "active_threat_count": len(self._state.active_threats),
            "blocked_ip_count": len(self._state.blocked_ips),
        })
        state_snap = self._state.to_dict()

        # ── REASON ───────────────────────────────────────────────────────
        # Prefer LangGraph + DeepSeek when available; fallback to keyword scorer.
        deepseek_key = (
            context.get("deepseek_api_key")
            or os.getenv("DEEPSEEK_API_KEY", "")
        )
        lg_result: dict | None = None
        if _LANGGRAPH_AVAILABLE and deepseek_key:
            try:
                _step("REASON", "Invoking LangGraph + DeepSeek reasoner…")
                lg_result = await _lg_reason(
                    intent=intent,
                    system_state=state_snap,
                    observations=context,
                    api_key=deepseek_key,
                )
                lg_class_str = lg_result.get("intent_class", "UNKNOWN").upper()
                try:
                    intent_class = IntentClass(lg_class_str)
                except ValueError:
                    intent_class = IntentClass.UNKNOWN
                confidence = float(lg_result.get("confidence", 0.5))
                _step("REASON",
                      f"DeepSeek classified as {intent_class.value} "
                      f"(confidence={confidence:.1%})",
                      {
                          "intent_class": intent_class.value,
                          "confidence": confidence,
                          "deepseek_reasoning": lg_result.get("deepseek_reasoning", "")[:500],
                          "engine": "langgraph+deepseek",
                      })
            except Exception as _lg_exc:
                logger.warning("[TRIAGE] LangGraph reasoner failed (%s) — falling back to keywords", _lg_exc)
                lg_result = None
                intent_class, confidence = _classify_intent(intent)
                _step("REASON",
                      f"[keyword fallback] Classified as {intent_class.value} "
                      f"(confidence={confidence:.1%})",
                      {"intent_class": intent_class.value, "confidence": confidence})
        else:
            intent_class, confidence = _classify_intent(intent)
            engine_label = "keyword" if not _LANGGRAPH_AVAILABLE else "keyword (no DEEPSEEK_API_KEY)"
            _step("REASON", f"[{engine_label}] Classified as {intent_class.value} (confidence={confidence:.1%})", {
                "intent_class": intent_class.value,
                "confidence": confidence,
            })

        # Build execution plan — honour DeepSeek's plan when available
        if lg_result and lg_result.get("action_plan"):
            plan = [
                GoalStep(
                    step_id=uuid.uuid4().hex[:8],
                    agent=s["agent"],
                    action=s["action"],
                    kwargs=s.get("kwargs", {}),
                )
                for s in lg_result["action_plan"]
                if isinstance(s, dict) and s.get("agent") and s.get("action")
            ] or self._build_plan(intent_class, intent, context)
        else:
            plan = self._build_plan(intent_class, intent, context)

        _step("REASON", f"Execution plan built: {len(plan)} step(s)", {
            "steps": [s.to_dict() for s in plan],
        })

        task = GoalTask(
            task_id=task_id,
            intent=intent,
            intent_class=intent_class,
            confidence=confidence,
            created_at=now,
            steps=plan,
            status="running",
            react_steps=react_steps,
        )
        self._state.ongoing_tasks[task_id] = task

        await self._bus.publish(Event("triage.plan", {
            "task_id": task_id,
            "intent_class": intent_class.value,
            "confidence": round(confidence, 3),
            "plan": [s.to_dict() for s in plan],
        }))

        # ── ACT ──────────────────────────────────────────────────────────
        actions_taken: list[str] = []
        findings: list[dict] = []
        outcome = "success"

        for step in plan:
            _step("ACT", f"Delegating to agent={step.agent!r}: {step.action}")
            await self._bus.publish(Event("triage.delegated", {
                "task_id": task_id,
                "step_id": step.step_id,
                "agent": step.agent,
                "action": step.action,
            }))
            step.status = "running"
            try:
                result = await self._dispatch(step)
                step.status = "done"
                step.result = result
                actions_taken.append(step.action)
                if isinstance(result, dict):
                    if "findings" in result:
                        findings.extend(result["findings"])
                elif isinstance(result, list):
                    findings.extend(result)
            except Exception as exc:
                step.status = "failed"
                step.error = str(exc)
                logger.warning("[TRIAGE] Step %s failed (%s): %s",
                               step.step_id, step.agent, exc)
                if outcome == "success":
                    outcome = "partial"

        # ── LEARN ─────────────────────────────────────────────────────────
        recommendations = self._build_recommendations(intent_class, findings)
        # Prepend DeepSeek recommendations when available (they are more specific)
        if lg_result and lg_result.get("recommendations"):
            ds_recs = [r for r in lg_result["recommendations"] if r not in recommendations]
            recommendations = ds_recs + recommendations
        self._update_threat_level()
        task.status = "completed" if outcome != "failed" else "failed"
        self._state.last_updated = datetime.now(timezone.utc).isoformat()

        _step("LEARN", f"Outcome={outcome}. {len(findings)} finding(s). "
              f"{len(recommendations)} recommendation(s).", {
            "outcome": outcome,
            "findings_count": len(findings),
        })

        duration_ms = round((time.monotonic() - start_ts) * 1000, 2)
        triage_result = TriageResult(
            task_id=task_id,
            intent=intent,
            intent_class=intent_class.value,
            confidence=confidence,
            plan=[s.to_dict() for s in plan],
            outcome=outcome,
            actions_taken=actions_taken,
            findings=findings[:50],
            recommendations=recommendations,
            duration_ms=duration_ms,
            system_state_snapshot=state_snap,
            react_steps=react_steps,
        )

        del self._state.ongoing_tasks[task_id]
        self._history.append(triage_result.to_dict())
        if len(self._history) > 500:
            self._history = self._history[-500:]

        await self._bus.publish(Event("triage.completed", {
            "task_id": task_id,
            "outcome": outcome,
            "intent_class": intent_class.value,
            "findings_count": len(findings),
            "duration_ms": duration_ms,
        }))

        return triage_result

    # ------------------------------------------------------------------
    # Plan construction
    # ------------------------------------------------------------------

    def _build_plan(
        self,
        intent_class: IntentClass,
        intent_text: str,
        context: dict,
    ) -> list[GoalStep]:
        """Decompose an intent class into an ordered list of GoalSteps."""

        def step(agent: str, action: str, **kwargs) -> GoalStep:
            return GoalStep(
                step_id=uuid.uuid4().hex[:8],
                agent=agent,
                action=action,
                kwargs=dict(kwargs),
            )

        text = intent_text.lower()
        target_ip = context.get("target_ip", "")

        if intent_class == IntentClass.THREAT_RESPONSE:
            plan: list[GoalStep] = [
                step("smart_firewall", "Pull firewall threat statistics"),
                step("malware_scanner", "Malware process scan — active threat response"),
            ]
            if target_ip:
                plan.append(step("ips", "Block target IP", ip=target_ip, duration=3600))
            return plan

        if intent_class == IntentClass.THREAT_HUNT:
            return [
                step("malware_scanner", "Full malware process scan"),
                step("smart_firewall", "Firewall detection statistics"),
                step("ids", "Recent IDS alert summary"),
            ]

        if intent_class == IntentClass.NETWORK_OPS:
            targets = context.get("targets") or ["192.168.1.0/24"]
            return [
                step("auditor", "Network audit — open service discovery", targets=targets),
                step("smart_firewall", "Firewall statistics post network scan"),
            ]

        if intent_class == IntentClass.SYSTEM_AUDIT:
            return [
                step("malware_scanner", "Malware scan — audit baseline"),
                step("smart_firewall", "Firewall rule and block-history audit"),
                step("ids", "IDS alert history review"),
                step("web_browsing", "Web-browsing safety statistics"),
            ]

        if intent_class == IntentClass.CLOAKING_OPS:
            return [
                step("cloaking", "Activate IP cloaking layer"),
                step("wifi_stealth", "Enable WiFi stealth mode"),
            ]

        if intent_class == IntentClass.REPORT_GEN:
            return [
                step("smart_firewall", "Collect firewall report data"),
                step("malware_scanner", "Collect malware scan data"),
                step("system_state", "Assemble full system state snapshot"),
            ]

        if intent_class == IntentClass.AGENT_CTRL:
            agent_name = _extract_agent_name(text)
            verb = "start" if any(
                kw in text for kw in ("start", "enable", "activate", "turn on")
            ) else "stop"
            return [step("agent_ctrl", f"{verb.title()} agent: {agent_name}",
                         agent_name=agent_name, action=verb)]

        # STATUS_QUERY and UNKNOWN both default to a safe state snapshot
        return [step("system_state", "System state snapshot")]

    # ------------------------------------------------------------------
    # Agent dispatch
    # ------------------------------------------------------------------

    async def _dispatch(self, step: GoalStep) -> Any:
        """Route a GoalStep to the appropriate sub-agent and return its result."""
        agent = step.agent
        kw = step.kwargs

        if agent == "smart_firewall":
            fw = self.engine.smart_firewall
            self._state.agent_statuses["smart_firewall"] = "active"
            return fw.get_stats()

        if agent == "malware_scanner":
            ml = self._get_malware_agent()
            self._state.agent_statuses["malware_scanner"] = "scanning"
            report = await ml.run_cycle()
            self._state.agent_statuses["malware_scanner"] = "idle"
            return {
                "risk_level": report.risk_level,
                "threat_score": report.threat_score,
                "findings": list(report.threats),
            }

        if agent == "ids":
            ids = self.engine.ids
            self._state.agent_statuses["ids"] = "active"
            alerts = ids.alerts
            return {
                "alert_count": len(alerts),
                "findings": [
                    {
                        "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                        "category": a.category.value if hasattr(a.category, "value") else str(a.category),
                        "source_ip": a.source_ip,
                        "description": a.description,
                        "timestamp": a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp),
                    }
                    for a in alerts[-20:]
                ],
            }

        if agent == "ips":
            ips = self.engine.ips
            ip = kw.get("ip", "")
            duration = kw.get("duration", 3600)
            if ip:
                from network_guardian.ips import BlockReason
                entry = await ips.block_ip(
                    ip,
                    reason=BlockReason.MANUAL,
                    duration=duration,
                    description="Blocked via TriageAgent",
                )
                if entry:
                    self._state.blocked_ips.add(ip)
                    return {"blocked": ip, "duration": duration}
            return {"blocked": None}

        if agent == "auditor":
            targets = kw.get("targets", ["127.0.0.1"])
            auditor = self.engine.auditor
            self._state.agent_statuses["auditor"] = "scanning"
            raw_findings = await auditor.run_audit(targets)
            self._state.agent_statuses["auditor"] = "idle"
            return {
                "findings": [
                    {
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        "host": f.host,
                        "port": f.port,
                        "recommendation": f.recommendation,
                    }
                    for f in raw_findings
                ]
            }

        if agent == "web_browsing":
            wb = self.engine.web_browsing
            self._state.agent_statuses["web_browsing"] = "active"
            return wb.get_stats()

        if agent == "cloaking":
            try:
                _cl = self.engine.cloaking
                self._state.agent_statuses["cloaking"] = "active"
                return {"status": "cloaking_activated"}
            except Exception as exc:
                return {"status": "cloaking_unavailable", "error": str(exc)}

        if agent == "wifi_stealth":
            try:
                _ws = self.engine.wifi_stealth
                self._state.agent_statuses["wifi_stealth"] = "active"
                return {"status": "wifi_stealth_activated"}
            except Exception as exc:
                return {"status": "wifi_stealth_unavailable", "error": str(exc)}

        if agent == "system_state":
            return self._state.to_dict()

        if agent == "agent_ctrl":
            return await self._handle_agent_ctrl(
                kw.get("agent_name", "unknown"),
                kw.get("action", "status"),
            )

        logger.warning("[TRIAGE] Unknown dispatch target: %s", agent)
        return None

    async def _handle_agent_ctrl(self, agent_name: str, action: str) -> dict:
        """Start or stop a named sub-agent."""
        agent_map = {
            "smart_firewall":    lambda: self.engine.smart_firewall,
            "web_browsing":      lambda: self.engine.web_browsing,
            "malware_scanner":   self._get_malware_agent,
            "ransomware_monitor": self._get_ransomware_agent,
        }
        factory = agent_map.get(agent_name)
        if factory is None:
            return {"error": f"Unknown agent: {agent_name}"}

        agent = factory()
        if action == "start" and hasattr(agent, "start"):
            agent.start()
        elif action == "stop" and hasattr(agent, "stop"):
            fn = agent.stop
            if asyncio.iscoroutinefunction(fn):
                await fn()
            else:
                fn()

        running = getattr(agent, "is_running", None)
        status = (running() if callable(running) else bool(running)) and "running" or "stopped"
        self._state.agent_statuses[agent_name] = status
        return {"agent": agent_name, "action": action, "status": status}

    # ------------------------------------------------------------------
    # Lazily-instantiated optional agents
    # ------------------------------------------------------------------

    def _get_malware_agent(self):
        if self._malware_agent is None:
            from network_guardian.agent.malware_react_agent import MalwareReActAgent
            self._malware_agent = MalwareReActAgent(
                event_bus=self._bus,
                auto_kill=False,
            )
        return self._malware_agent

    def _get_ransomware_agent(self):
        if self._ransomware_agent is None:
            from network_guardian.agent.ransomware_react_agent import RansomwareReActAgent
            self._ransomware_agent = RansomwareReActAgent(
                event_bus=self._bus,
                auto_quarantine=False,
            )
        return self._ransomware_agent

    # ------------------------------------------------------------------
    # Event handlers — maintain SystemState in real time
    # ------------------------------------------------------------------

    async def _on_ids_alert(self, event: Event) -> None:
        data = event.data
        severity = data.get("severity", "low")
        self._state.active_threats.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "category": data.get("category", "unknown"),
            "source_ip": data.get("source_ip", ""),
            "description": data.get("description", ""),
        })
        if len(self._state.active_threats) > 500:
            self._state.active_threats = self._state.active_threats[-500:]
        self._state.threat_counts[severity] = (
            self._state.threat_counts.get(severity, 0) + 1
        )
        self._state.recent_events.append({
            "topic": "ids.alert",
            "data": data,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        self._update_threat_level()

    async def _on_firewall_event(self, event: Event) -> None:
        ip = event.data.get("source_ip", "")
        if ip:
            self._state.blocked_ips.add(ip)
        self._state.recent_events.append({
            "topic": "firewall.injection.blocked",
            "data": event.data,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    async def _on_anomaly(self, event: Event) -> None:
        self._state.recent_events.append({
            "topic": "monitor.anomaly",
            "data": event.data,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        if event.data.get("severity") in ("high", "critical"):
            self._bump_threat_level()

    async def _on_probe_event(self, event: Event) -> None:
        self._state.recent_events.append({
            "topic": event.topic,
            "data": event.data,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        if event.topic == "probe.discovery.rogue_ap":
            self._bump_threat_level()

    async def _on_triage_command(self, event: Event) -> None:
        """Handle goals injected via the event bus (dashboard, remote agents, etc.)."""
        intent = event.data.get("intent", "").strip()
        context = event.data.get("context", {})
        if not intent:
            return
        try:
            result = await self.triage(intent, context)
            logger.info("[TRIAGE] Bus command completed — outcome=%s task=%s",
                        result.outcome, result.task_id)
        except Exception as exc:
            logger.exception("[TRIAGE] Bus command failed: %s", exc)
            await self._bus.publish(Event("triage.error", {
                "intent": intent,
                "error": str(exc),
            }))

    # ------------------------------------------------------------------
    # Threat level management
    # ------------------------------------------------------------------

    def _update_threat_level(self) -> None:
        """Recompute aggregate threat level from current threat counts."""
        c = self._state.threat_counts
        if c.get("critical", 0) >= 1:
            level = "red"
        elif c.get("high", 0) >= 3:
            level = "orange"
        elif c.get("high", 0) >= 1 or c.get("medium", 0) >= 5:
            level = "yellow"
        else:
            level = "green"
        self._state.threat_level = level
        self._state.last_updated = datetime.now(timezone.utc).isoformat()

    def _bump_threat_level(self) -> None:
        """Escalate threat level by one step (never exceeds red)."""
        idx = self._THREAT_LEVELS.index(self._state.threat_level)
        if idx < len(self._THREAT_LEVELS) - 1:
            self._state.threat_level = self._THREAT_LEVELS[idx + 1]
        self._state.last_updated = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _build_recommendations(
        self,
        intent_class: IntentClass,
        findings: list[dict],
    ) -> list[str]:
        recs: list[str] = []

        if self._state.threat_level in ("orange", "red"):
            recs.append(
                "Immediate review required — system threat level is elevated."
            )

        if intent_class == IntentClass.THREAT_RESPONSE:
            recs.append(
                "Verify blocked IPs are not legitimate internal hosts "
                "before extending block duration."
            )

        if intent_class == IntentClass.THREAT_HUNT:
            if any(f.get("severity") == "critical" for f in findings):
                recs.append(
                    "Critical findings detected — escalate to incident response immediately."
                )
            else:
                recs.append(
                    "No critical threats found — schedule a follow-up scan in 24 hours "
                    "to confirm clean state."
                )

        if intent_class == IntentClass.SYSTEM_AUDIT:
            recs.append(
                "Export audit findings to PDF for compliance documentation."
            )

        if intent_class == IntentClass.NETWORK_OPS:
            recs.append(
                "Cross-reference discovered hosts with your asset inventory "
                "and flag any unknown devices."
            )

        if intent_class == IntentClass.CLOAKING_OPS:
            recs.append(
                "Confirm cloaking is active before transmitting sensitive traffic."
            )

        if not recs:
            recs.append(
                "System operating normally — maintain scheduled scans and monitoring."
            )
        return recs

    # ------------------------------------------------------------------
    # Periodic status broadcast
    # ------------------------------------------------------------------

    async def _status_broadcast_loop(self) -> None:
        """Publish ``triage.status`` every 60 seconds while running."""
        while self._running:
            await asyncio.sleep(60)
            if not self._running:
                break
            try:
                await self._bus.publish(Event("triage.status", self._state.to_dict()))
            except Exception:
                logger.exception("[TRIAGE] Status broadcast error")

    # ------------------------------------------------------------------
    # Public read-only accessors
    # ------------------------------------------------------------------

    def get_system_state(self) -> dict:
        """Return a live snapshot of SystemState as a plain dict."""
        return self._state.to_dict()

    def get_threat_level(self) -> str:
        """Return the current aggregate threat level string."""
        return self._state.threat_level

    def get_history(self, limit: int = 50) -> list[dict]:
        """Return the most recent completed task records."""
        return self._history[-limit:]

    def dashboard_summary(self) -> dict:
        """Compact summary suitable for embedding in dashboard API responses."""
        s = self._state
        return {
            "threat_level": s.threat_level,
            "active_threats_count": len(s.active_threats),
            "blocked_ips_count": len(s.blocked_ips),
            "threat_counts": s.threat_counts,
            "agent_statuses": s.agent_statuses,
            "ongoing_tasks_count": len(s.ongoing_tasks),
            "task_history_count": len(self._history),
            "is_running": self._running,
        }
