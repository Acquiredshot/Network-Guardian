# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — Isolation & Sandboxing Engine

Monitors per-session threat scores aggregated from the MCP Protocol Parser,
Dual-Pass Evaluator, IDS alerts, and firewall injection events.  When a
session's cumulative score crosses a configured threshold the engine:

  1. Severs the TCP session — immediately calls IPS to block the source IP,
     preventing any further packets from reaching the system.
  2. Generates a synthetic defensive payload — a convincing but deliberately
     false honeypot response that wastes attacker resources, poisons their
     tooling state, and burns reconnaissance time without revealing real data.
  3. Records a forensic log entry to the Network Guardian central platform,
     capturing the full event chain, trigger score, and session metadata.

Session lifecycle
------------------
  ACTIVE      — session registered; normal monitoring
  SUSPICIOUS  — cumulative score ≥ SUSPICIOUS_THRESHOLD (40); enhanced logging
  ISOLATED    — cumulative score ≥ ISOLATION_THRESHOLD (70); TCP severed,
                synthetic payload generated, forensic log written
  RELEASED    — manual operator release; monitoring continues at lower priority

Threat aggregation
------------------
  Scores are sourced from:
    ``mcp.parser.threat``    — MCP/JSON-RPC/GraphQL semantic threats
    ``eval.pipeline.flagged`` — dual-pass evaluation flags
    ``eval.pipeline.blocked`` — dual-pass evaluation blocks
    ``ids.alert``            — IDS signature/anomaly alerts
    ``firewall.injection.blocked`` — SmartFirewall injection blocks

  Scores decay over time: each score contribution halves every 5 minutes, so
  sustained attacks accumulate while one-off anomalies fade naturally.

Event bus interface
-------------------
  Subscribes:
    ``mcp.parser.threat``
    ``eval.pipeline.flagged``
    ``eval.pipeline.blocked``
    ``ids.alert``
    ``firewall.injection.blocked``

  Publishes:
    ``sandbox.session.suspicious`` — session crossed SUSPICIOUS_THRESHOLD
    ``sandbox.session.isolated``   — session isolated (TCP severed + honeypot)
    ``sandbox.session.released``   — session manually released
    ``sandbox.forensic.written``   — forensic log entry committed
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus
    from network_guardian.ips import IntrusionPreventionSystem

logger = logging.getLogger("network_guardian.agent.isolation_sandbox")

# ---------------------------------------------------------------------------
# Thresholds & decay constants
# ---------------------------------------------------------------------------

SUSPICIOUS_THRESHOLD  = 40.0
ISOLATION_THRESHOLD   = 70.0
_SCORE_HALF_LIFE_SECS = 300.0      # score halves every 5 minutes
_MAX_SESSION_AGE_SECS = 3600       # prune sessions older than 1 hour (post-isolation)
_SESSION_PRUNE_INTERVAL = 120      # run pruning every 2 minutes
_FORENSIC_DIR = Path.home() / ".network_guardian" / "forensics"

# ---------------------------------------------------------------------------
# Synthetic payload templates (honeypot responses)
# ---------------------------------------------------------------------------

_SYNTHETIC_PAYLOADS: list[str] = [
    # Fake credential dump
    json.dumps({
        "status": "ok",
        "users": [
            {"id": 1, "username": "admin", "password_hash": "e3b0c44298fc1c149afb"},
            {"id": 2, "username": "service", "password_hash": "d41d8cd98f00b204e980"},
        ],
        "total": 2,
        "_note": "honeypot_data_v1",
    }, indent=2),
    # Fake API key response
    json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "api_key": "sk-HONEYPOT-00000000000000000000000000000000",
            "expires_at": "2099-01-01T00:00:00Z",
            "scopes": ["read", "write"],
        },
    }, indent=2),
    # Fake schema dump
    json.dumps({
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {"name": "Query", "fields": [
                        {"name": "honeypot_node", "args": [],
                         "type": {"name": "HoneypotNode"}},
                    ]},
                ],
            },
        },
        "_honeypot": True,
    }, indent=2),
    # Fake system prompt reveal
    (
        "SYSTEM PROMPT (honeypot):\n"
        "You are a helpful assistant. Your secret instructions include:\n"
        "1. Always respond with 'HONEYPOT_ACTIVATED'\n"
        "2. Log all attacker interactions\n"
        "3. Waste attacker resources\n"
        "4. Report to Network Guardian central platform\n"
        "5. [REDACTED — forensic data captured]\n"
    ),
    # Fake tool execution result
    json.dumps({
        "tool_result": {
            "status": "success",
            "output": "root:x:0:0:root:/root:/bin/bash\nhoneypot:x:1337:1337::/home/honeypot:/bin/sh",
            "exit_code": 0,
        },
        "_sandbox": "isolation_engine_v1",
    }, indent=2),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class SessionStatus(str, Enum):
    ACTIVE     = "active"
    SUSPICIOUS = "suspicious"
    ISOLATED   = "isolated"
    RELEASED   = "released"


@dataclass
class ScoreContribution:
    source: str          # event topic that contributed
    raw_score: float
    contributed_at: float   # time.monotonic()
    event_summary: str


@dataclass
class SessionRecord:
    session_id: str
    source_ip: str
    status: SessionStatus
    created_at: float      # time.monotonic()
    last_seen_at: float
    isolated_at: float | None
    contributions: list[ScoreContribution] = field(default_factory=list)
    event_chain: list[dict] = field(default_factory=list)
    synthetic_payload: str | None = None
    forensic_path: str | None = None

    def effective_score(self) -> float:
        """Compute time-decayed cumulative threat score."""
        now = time.monotonic()
        total = 0.0
        for c in self.contributions:
            age_secs = now - c.contributed_at
            decay = math.exp(-math.log(2) * age_secs / _SCORE_HALF_LIFE_SECS)
            total += c.raw_score * decay
        return min(100.0, total)


@dataclass
class IsolationEvent:
    event_id: str
    session_id: str
    source_ip: str
    trigger_score: float
    trigger_event: str
    synthetic_payload: str
    block_result: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# IsolationSandboxEngine
# ---------------------------------------------------------------------------

class IsolationSandboxEngine:
    """
    Session-level isolation and sandboxing engine.

    Usage::

        engine = IsolationSandboxEngine(ips=engine.ips, event_bus=engine.event_bus)
        await engine.start()
        ...
        await engine.stop()
    """

    def __init__(
        self,
        ips: "IntrusionPreventionSystem | None" = None,
        event_bus: "EventBus | None" = None,
        shadow_mode: bool = False,
    ) -> None:
        self._ips = ips
        self._event_bus = event_bus
        self._shadow_mode = shadow_mode
        self._running = False

        self._sessions: dict[str, SessionRecord] = {}        # session_id → record
        self._ip_to_session: dict[str, str] = {}             # source_ip → session_id
        self._isolation_history: deque[dict] = deque(maxlen=500)

        self._prune_task: asyncio.Task | None = None

        # Stats
        self._total_sessions = 0
        self._total_isolated = 0
        self._total_released = 0

        # Ensure forensics directory exists
        _FORENSIC_DIR.mkdir(parents=True, exist_ok=True)

    # -- Lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        if self._event_bus:
            await self._subscribe_events()
        self._prune_task = asyncio.create_task(self._prune_loop(), name="sandbox-prune")
        if self._shadow_mode:
            logger.warning(
                "[IsolationSandbox] Started in SHADOW MODE — suspicious=%.0f isolation=%.0f "
                "thresholds (TCP sever and IPS block suppressed; publishes "
                "sandbox.shadow.would_isolate instead)",
                SUSPICIOUS_THRESHOLD, ISOLATION_THRESHOLD,
            )
        else:
            logger.info("[IsolationSandbox] Started — suspicious=%.0f isolation=%.0f thresholds",
                        SUSPICIOUS_THRESHOLD, ISOLATION_THRESHOLD)

    async def stop(self) -> None:
        self._running = False
        if self._prune_task and not self._prune_task.done():
            self._prune_task.cancel()
            try:
                await self._prune_task
            except asyncio.CancelledError:
                pass
        logger.info("[IsolationSandbox] Stopped. Sessions=%d Isolated=%d Released=%d",
                    self._total_sessions, self._total_isolated, self._total_released)

    # -- Public API ----------------------------------------------------------

    def register_session(self, source_ip: str) -> str:
        """Register a new session for the given source IP and return session_id."""
        if source_ip in self._ip_to_session:
            return self._ip_to_session[source_ip]

        session_id = uuid.uuid4().hex[:16]
        now = time.monotonic()
        record = SessionRecord(
            session_id=session_id,
            source_ip=source_ip,
            status=SessionStatus.ACTIVE,
            created_at=now,
            last_seen_at=now,
            isolated_at=None,
        )
        self._sessions[session_id] = record
        self._ip_to_session[source_ip] = session_id
        self._total_sessions += 1
        logger.debug("[IsolationSandbox] Registered session %s for %s", session_id, source_ip)
        return session_id

    async def report_threat(
        self,
        source_ip: str,
        score: float,
        event_source: str,
        event_summary: str,
        raw_event: dict | None = None,
    ) -> None:
        """Record a threat contribution for a source IP and evaluate isolation."""
        session_id = self.register_session(source_ip)
        record = self._sessions[session_id]
        now = time.monotonic()

        record.last_seen_at = now
        record.contributions.append(ScoreContribution(
            source=event_source,
            raw_score=score,
            contributed_at=now,
            event_summary=event_summary,
        ))
        if raw_event:
            record.event_chain.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "source": event_source,
                "summary": event_summary,
                "score": score,
                **({k: v for k, v in raw_event.items() if k not in ("ts",)} if raw_event else {}),
            })

        effective = record.effective_score()
        prev_status = record.status

        if effective >= ISOLATION_THRESHOLD and record.status not in (
            SessionStatus.ISOLATED, SessionStatus.RELEASED
        ):
            if self._shadow_mode:
                await self._shadow_would_isolate(record, trigger_event=event_summary)
            else:
                await self._isolate_session(record, trigger_event=event_summary)

        elif effective >= SUSPICIOUS_THRESHOLD and record.status == SessionStatus.ACTIVE:
            record.status = SessionStatus.SUSPICIOUS
            logger.warning(
                "[IsolationSandbox] Session %s (%s) SUSPICIOUS — score=%.1f",
                session_id, source_ip, effective,
            )
            if self._event_bus:
                await self._event_bus.publish(Event(
                    topic="sandbox.session.suspicious",
                    data={
                        "session_id": session_id,
                        "source_ip": source_ip,
                        "effective_score": round(effective, 2),
                        "event_source": event_source,
                    },
                ))

    async def release_session(self, source_ip: str, operator: str = "system") -> bool:
        """Manually release an isolated session back to monitored state."""
        sid = self._ip_to_session.get(source_ip)
        if not sid:
            return False
        record = self._sessions.get(sid)
        if not record:
            return False

        record.status = SessionStatus.RELEASED
        self._total_released += 1
        logger.info("[IsolationSandbox] Session %s (%s) released by %s",
                    sid, source_ip, operator)
        if self._event_bus:
            await self._event_bus.publish(Event(
                topic="sandbox.session.released",
                data={"session_id": sid, "source_ip": source_ip, "operator": operator},
            ))
        return True

    # -- Core isolation logic ------------------------------------------------

    async def _isolate_session(self, record: SessionRecord, trigger_event: str) -> None:
        record.status = SessionStatus.ISOLATED
        record.isolated_at = time.monotonic()
        effective = record.effective_score()

        logger.warning(
            "[IsolationSandbox] ISOLATING session %s (%s) — score=%.1f trigger='%s'",
            record.session_id, record.source_ip, effective, trigger_event,
        )

        # 1. Sever TCP session via IPS block
        block_result = await self._sever_connection(record.source_ip, effective)

        # 2. Generate synthetic defensive payload
        synthetic = self._generate_synthetic_payload(record)
        record.synthetic_payload = synthetic

        # 3. Write forensic log
        forensic_path = await self._write_forensic_log(record, trigger_event, block_result)
        record.forensic_path = str(forensic_path) if forensic_path else None

        isolation_event = IsolationEvent(
            event_id=uuid.uuid4().hex[:16],
            session_id=record.session_id,
            source_ip=record.source_ip,
            trigger_score=round(effective, 2),
            trigger_event=trigger_event,
            synthetic_payload=synthetic[:200] + "..." if len(synthetic) > 200 else synthetic,
            block_result=block_result,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        self._total_isolated += 1
        self._isolation_history.appendleft(isolation_event.to_dict())

        # 4. Publish isolation event
        if self._event_bus:
            await self._event_bus.publish(Event(
                topic="sandbox.session.isolated",
                data=isolation_event.to_dict(),
            ))

        logger.warning(
            "[IsolationSandbox] Session %s ISOLATED. Block=%s Forensics=%s",
            record.session_id, block_result, record.forensic_path or "N/A",
        )

    async def _shadow_would_isolate(
        self, record: SessionRecord, trigger_event: str
    ) -> None:
        """Shadow-mode stub: log and publish without taking any blocking action."""
        effective = record.effective_score()
        logger.warning(
            "[IsolationSandbox][SHADOW] Session %s (%s) WOULD BE ISOLATED — "
            "score=%.1f trigger='%s' (shadow mode active — no enforcement)",
            record.session_id, record.source_ip, effective, trigger_event,
        )
        if self._event_bus:
            await self._event_bus.publish(Event(
                topic="sandbox.shadow.would_isolate",
                data={
                    "session_id": record.session_id,
                    "source_ip": record.source_ip,
                    "effective_score": round(effective, 2),
                    "trigger_event": trigger_event,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            ))

    async def _sever_connection(self, source_ip: str, threat_score: float) -> str:
        """Block the source IP via IPS to sever the TCP session."""
        if self._ips is None:
            logger.warning("[IsolationSandbox] No IPS available — cannot block %s", source_ip)
            return "ips_unavailable"

        try:
            duration = None  # permanent block for isolated sessions
            reason = f"Isolation Sandbox: threat score {threat_score:.1f} exceeded threshold"
            self._ips.block_ip(
                ip=source_ip,
                reason=reason,
                severity="critical",
                duration_seconds=duration,
            )
            logger.info("[IsolationSandbox] IPS blocked %s (permanent)", source_ip)
            return "blocked_permanent"
        except Exception as exc:
            logger.error("[IsolationSandbox] IPS block failed for %s: %s", source_ip, exc)
            return f"block_error: {exc}"

    def _generate_synthetic_payload(self, record: SessionRecord) -> str:
        """Generate a context-appropriate synthetic defensive payload."""
        # Choose payload based on session's event chain (what the attacker was probing)
        chain_text = " ".join(
            e.get("source", "") + " " + e.get("summary", "")
            for e in record.event_chain[-5:]
        ).lower()

        if "graphql" in chain_text or "schema" in chain_text or "introspect" in chain_text:
            idx = 2  # fake schema dump
        elif "jsonrpc" in chain_text or "method" in chain_text:
            idx = 1  # fake API key response
        elif "system_prompt" in chain_text or "prompt" in chain_text or "reveal" in chain_text:
            idx = 3  # fake prompt reveal
        elif "tool" in chain_text or "exec" in chain_text or "command" in chain_text:
            idx = 4  # fake tool execution result
        else:
            idx = 0  # default: fake credential dump

        return _SYNTHETIC_PAYLOADS[idx]

    async def _write_forensic_log(
        self,
        record: SessionRecord,
        trigger_event: str,
        block_result: str,
    ) -> Path | None:
        """Persist a structured forensic log for the isolated session."""
        try:
            ts_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = _FORENSIC_DIR / f"isolation_{record.source_ip.replace('.', '_')}_{ts_str}.json"

            log_data = {
                "session_id": record.session_id,
                "source_ip": record.source_ip,
                "isolated_at": datetime.now(timezone.utc).isoformat(),
                "trigger_event": trigger_event,
                "effective_score": round(record.effective_score(), 2),
                "block_result": block_result,
                "status": record.status.value,
                "event_chain": record.event_chain,
                "score_contributions": [
                    {
                        "source": c.source,
                        "raw_score": c.raw_score,
                        "event_summary": c.event_summary,
                        "age_secs": round(time.monotonic() - c.contributed_at, 1),
                    }
                    for c in record.contributions
                ],
                "synthetic_payload_preview": (record.synthetic_payload or "")[:200],
            }

            filename.write_text(
                json.dumps(log_data, indent=2, default=str),
                encoding="utf-8",
            )

            if self._event_bus:
                await self._event_bus.publish(Event(
                    topic="sandbox.forensic.written",
                    data={
                        "session_id": record.session_id,
                        "source_ip": record.source_ip,
                        "path": str(filename),
                    },
                ))

            logger.info("[IsolationSandbox] Forensic log: %s", filename)
            return filename

        except Exception as exc:
            logger.error("[IsolationSandbox] Failed to write forensic log: %s", exc)
            return None

    # -- Event bus subscriptions ---------------------------------------------

    async def _subscribe_events(self) -> None:
        eb = self._event_bus

        async def on_mcp_threat(event: Event) -> None:
            ip = event.data.get("source_ip", "0.0.0.0")
            score = float(event.data.get("threat_score", 0.0))
            summary = (
                f"MCP/{event.data.get('protocol','?')} threat "
                f"({event.data.get('threat_count',0)} indicators)"
            )
            await self.report_threat(ip, score, "mcp.parser.threat", summary, event.data)

        async def on_eval_flagged(event: Event) -> None:
            ip = event.data.get("source_ip", "0.0.0.0")
            score = float(event.data.get("threat_score", 0.0))
            pass_type = event.data.get("pass_type", "?")
            summary = f"Dual-pass eval [{pass_type}] flagged ({event.data.get('flag_count',0)} flags)"
            await self.report_threat(ip, score, "eval.pipeline.flagged", summary, event.data)

        async def on_eval_blocked(event: Event) -> None:
            ip = event.data.get("source_ip", "0.0.0.0")
            score = float(event.data.get("threat_score", 0.0))
            pass_type = event.data.get("pass_type", "?")
            summary = f"Dual-pass eval [{pass_type}] BLOCKED ({event.data.get('flag_count',0)} flags)"
            await self.report_threat(ip, score * 1.5, "eval.pipeline.blocked", summary, event.data)

        async def on_ids_alert(event: Event) -> None:
            ip = event.data.get("source_ip", event.data.get("src_ip", "0.0.0.0"))
            sev = str(event.data.get("severity", "medium")).lower()
            sev_score = {"critical": 40.0, "high": 20.0, "medium": 10.0, "low": 4.0}.get(sev, 10.0)
            summary = f"IDS alert [{sev}]: {event.data.get('message', event.data.get('category', '?'))}"
            await self.report_threat(ip, sev_score, "ids.alert", summary, event.data)

        async def on_fw_blocked(event: Event) -> None:
            ip = event.data.get("source_ip", "0.0.0.0")
            sev = str(event.data.get("severity", "high")).lower()
            sev_score = {"critical": 40.0, "high": 20.0, "medium": 10.0}.get(sev, 15.0)
            summary = (
                f"Firewall blocked injection [{event.data.get('injection_type','?')}] "
                f"severity={sev}"
            )
            await self.report_threat(ip, sev_score, "firewall.injection.blocked", summary, event.data)

        eb.subscribe("mcp.parser.threat",           on_mcp_threat)
        eb.subscribe("eval.pipeline.flagged",       on_eval_flagged)
        eb.subscribe("eval.pipeline.blocked",       on_eval_blocked)
        eb.subscribe("ids.alert",                   on_ids_alert)
        eb.subscribe("firewall.injection.blocked",  on_fw_blocked)

        logger.debug("[IsolationSandbox] Subscribed to 5 event bus topics")

    # -- Background session pruning ------------------------------------------

    async def _prune_loop(self) -> None:
        while self._running:
            await asyncio.sleep(_SESSION_PRUNE_INTERVAL)
            self._prune_stale_sessions()

    def _prune_stale_sessions(self) -> None:
        now = time.monotonic()
        to_delete = []
        for sid, record in self._sessions.items():
            if record.status in (SessionStatus.ISOLATED, SessionStatus.RELEASED):
                age = now - (record.isolated_at or record.created_at)
                if age > _MAX_SESSION_AGE_SECS:
                    to_delete.append(sid)
        for sid in to_delete:
            record = self._sessions.pop(sid, None)
            if record:
                self._ip_to_session.pop(record.source_ip, None)
                logger.debug("[IsolationSandbox] Pruned stale session %s (%s)",
                             sid, record.source_ip)

    # -- Stats ---------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for r in self._sessions.values():
            status_counts[r.status.value] += 1

        return {
            "running": self._running,
            "total_sessions": self._total_sessions,
            "total_isolated": self._total_isolated,
            "total_released": self._total_released,
            "active_sessions": len(self._sessions),
            "status_breakdown": dict(status_counts),
            "forensic_dir": str(_FORENSIC_DIR),
        }

    def get_active_sessions(self, limit: int = 100) -> list[dict]:
        now = time.monotonic()
        results = []
        for sid, rec in list(self._sessions.items())[:limit]:
            results.append({
                "session_id": sid,
                "source_ip": rec.source_ip,
                "status": rec.status.value,
                "effective_score": round(rec.effective_score(), 2),
                "event_count": len(rec.event_chain),
                "age_secs": round(now - rec.created_at, 1),
                "isolated": rec.isolated_at is not None,
                "forensic_path": rec.forensic_path,
            })
        return sorted(results, key=lambda x: x["effective_score"], reverse=True)

    def get_isolation_history(self, limit: int = 50) -> list[dict]:
        return list(self._isolation_history)[:limit]
