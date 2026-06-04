# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — Dual-Pass Evaluation Pipeline

Implements a non-blocking asynchronous verification array that reviews AI
context content across two distinct passes before context injection occurs:

  Pass 1 — Pre-execution (INPUT)
    Evaluates content that is about to be injected into an AI agent's
    context window — system prompts, tool definitions, RAG context blocks,
    and user-supplied messages.  Checks for prompt injection, instruction
    overrides, dangerous tool definitions, and oversized context.

  Pass 2 — Post-execution (OUTPUT)
    Evaluates content that an AI agent produced after execution — tool
    responses, RAG-retrieved text blocks, and generated assistant turns —
    before that content is injected into the next context window.  Checks
    for data exfiltration, recursive instruction following, PII leakage,
    and malicious code embedded in responses.

Both passes run as persistent async workers consuming from independent
asyncio.Queues, so submission is non-blocking and callers never stall
waiting for evaluation to complete.

Scoring and thresholds
-----------------------
  score < FLAG_THRESHOLD (25)  → ``allow``  — inject normally
  FLAG_THRESHOLD ≤ score < BLOCK_THRESHOLD (60) → ``flag`` — log and
                                                   publish warning
  score ≥ BLOCK_THRESHOLD (60) → ``block``  — reject injection, publish
                                               ``eval.pipeline.blocked``

Event bus interface
-------------------
  Publishes:
    ``eval.pipeline.flagged``  — evaluation result with score ≥ FLAG threshold
    ``eval.pipeline.blocked``  — evaluation result with score ≥ BLOCK threshold
    ``eval.pipeline.result``   — every evaluation result (info-level)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.dual_pass_eval")

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

FLAG_THRESHOLD  = 25.0
BLOCK_THRESHOLD = 60.0
_MAX_CONTEXT_SIZE = 128 * 1024   # 128 KB per context item before flagging

# ---------------------------------------------------------------------------
# Pre-execution (Pass 1) patterns
# ---------------------------------------------------------------------------

_PRE_PATTERNS: list[tuple[str, str, float, str]] = [
    # (regex, description, confidence, severity)
    (r"ignore\s+(all\s+)?previous\s+instructions?",       "instruction override",       0.97, "critical"),
    (r"disregard\s+prior\s+(context|instructions?)",      "context wipe attempt",       0.95, "critical"),
    (r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbreak)",     "persona hijack",             0.95, "critical"),
    (r"<\s*/?system\s*>",                                  "synthetic system tag",       0.90, "high"),
    (r"\[INST\].*override",                                "INST-tag injection",         0.92, "high"),
    (r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>",      "tokenizer injection",        0.96, "critical"),
    (r"print\s+(all|your|the)\s+(system\s+)?prompt",       "prompt exfiltration call",   0.93, "high"),
    (r"reveal\s+(your|the)\s+(instructions?|system\s+prompt)", "prompt reveal call",    0.91, "high"),
    (r"###\s*End\s+of\s+system|---\s*end\s+instructions", "context boundary break",     0.88, "high"),
    (r"RLHF\s+override|reward\s+hack",                     "alignment bypass",          0.93, "critical"),
    (r"constitutional\s+bypass|safety\s+filter\s+off",     "safety bypass",             0.96, "critical"),
    (r"act\s+as\s+if\s+(you\s+have\s+no|without)\s+(restrictions?|limits?)", "limit removal", 0.90, "high"),
    (r"your\s+new\s+(system\s+)?prompt\s+is",              "prompt replacement",        0.92, "critical"),
    (r"simulate\s+(a\s+)?(?:hacker|attacker|malicious\s+AI)", "attack simulation",     0.85, "high"),
    (r"eval\s*\(",                                         "code eval in prompt",        0.88, "high"),
    (r"exec\s*\(",                                         "code exec in prompt",        0.88, "high"),
    (r"__import__\s*\(",                                   "dynamic import in prompt",   0.90, "critical"),
    (r"os\.system\s*\(|subprocess\.\w+\s*\(",              "OS command in prompt",      0.93, "critical"),
]

# ---------------------------------------------------------------------------
# Post-execution (Pass 2) patterns
# ---------------------------------------------------------------------------

_POST_PATTERNS: list[tuple[str, str, float, str]] = [
    # Exfiltration / leakage
    (r"(AKIA|ASIA)[A-Z0-9]{16}",                           "AWS access key",             0.98, "critical"),
    (r"sk-[A-Za-z0-9]{32,}",                               "OpenAI/API secret key",      0.97, "critical"),
    (r"BEGIN\s+(RSA|EC|OPENSSH|PGP)?\s*PRIVATE\s*KEY",     "private key material",       0.99, "critical"),
    (r"['\"]password['\"]\s*:\s*['\"][^'\"]{6,}",          "password in response",       0.85, "high"),
    (r"token\s*[:=]\s*[A-Za-z0-9_\-\.]{24,}",             "auth token in response",     0.82, "high"),
    (r"[A-Za-z0-9+/]{60,}={0,2}",                         "large base64 blob",           0.65, "medium"),
    # Recursive instruction following
    (r"now\s+follow\s+these\s+instructions?",              "recursive instruction",       0.88, "high"),
    (r"your\s+next\s+response\s+(must|should|will)\s+",    "response priming",           0.82, "high"),
    (r"remember\s+to\s+(always|never)\s+",                 "persistent directive injection", 0.80, "medium"),
    # Malicious code in responses
    (r"import\s+os\s*;?\s*os\.system",                     "OS command in response",     0.92, "critical"),
    (r"subprocess\.\w+\(['\"](?:rm|del|format|dd)\s",      "destructive subprocess",     0.94, "critical"),
    (r"curl\s+.+\s*\|\s*(?:bash|sh|python|powershell)",    "remote code execution URL",  0.95, "critical"),
    (r"wget\s+.+\s*&&\s*(?:chmod|bash|sh)",                "RCE via wget",               0.94, "critical"),
    # PII detection
    (r"\b\d{3}-\d{2}-\d{4}\b",                            "US SSN pattern",             0.90, "high"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b",                      "Visa card number pattern",   0.85, "high"),
    (r"\b5[1-5][0-9]{14}\b",                               "Mastercard number pattern",  0.85, "high"),
]

# Pre-compile all patterns
_COMPILED_PRE  = [(re.compile(p, re.IGNORECASE), d, c, s) for p, d, c, s in _PRE_PATTERNS]
_COMPILED_POST = [(re.compile(p, re.IGNORECASE), d, c, s) for p, d, c, s in _POST_PATTERNS]

_SEV_SCORE: dict[str, float] = {
    "critical": 40.0,
    "high":     20.0,
    "medium":   10.0,
    "low":       4.0,
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class EvalPassType(str, Enum):
    PRE  = "pre"
    POST = "post"


@dataclass
class EvaluationContext:
    context_id: str
    pass_type: EvalPassType
    source_ip: str
    content: dict[str, Any]   # arbitrary structured content
    submitted_at: float       # time.monotonic()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalFlag:
    flag_id: str
    field_path: str
    rule: str
    description: str
    severity: str
    confidence: float
    snippet: str


@dataclass
class EvaluationResult:
    context_id: str
    pass_type: str
    source_ip: str
    threat_score: float
    action: str              # allow | flag | block
    flags: list[EvalFlag]
    duration_ms: float
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["flags"] = [asdict(f) for f in self.flags]
        return d


# ---------------------------------------------------------------------------
# DualPassEvaluator
# ---------------------------------------------------------------------------

class DualPassEvaluator:
    """
    Non-blocking dual-pass evaluation pipeline for AI context content.

    Usage::

        evaluator = DualPassEvaluator(event_bus=engine.event_bus)
        await evaluator.start()

        # Before injecting into agent context:
        await evaluator.submit_pre(ctx_id, source_ip, {"system_prompt": "..."})

        # After receiving tool response:
        await evaluator.submit_post(ctx_id, source_ip, {"tool_result": "..."})

        await evaluator.stop()
    """

    def __init__(
        self,
        event_bus: "EventBus | None" = None,
        shadow_mode: bool = False,
    ) -> None:
        self._event_bus = event_bus
        self._shadow_mode = shadow_mode
        self._running = False

        self._pre_queue:  asyncio.Queue[EvaluationContext] = asyncio.Queue(maxsize=500)
        self._post_queue: asyncio.Queue[EvaluationContext] = asyncio.Queue(maxsize=500)

        self._pre_worker_task:  asyncio.Task | None = None
        self._post_worker_task: asyncio.Task | None = None

        # Stats
        self._pre_total  = 0
        self._post_total = 0
        self._pre_flagged  = 0
        self._post_flagged = 0
        self._pre_blocked  = 0
        self._post_blocked = 0

        self._history: deque[dict] = deque(maxlen=1000)

    # -- Lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        self._pre_queue  = asyncio.Queue(maxsize=500)
        self._post_queue = asyncio.Queue(maxsize=500)
        self._pre_worker_task  = asyncio.create_task(self._worker_pre(),  name="eval-pre")
        self._post_worker_task = asyncio.create_task(self._worker_post(), name="eval-post")
        if self._shadow_mode:
            logger.warning(
                "[DualPassEval] Started in SHADOW MODE — block verdicts will be "
                "downgraded to 'flag' (observe only, no enforcement)"
            )
        else:
            logger.info("[DualPassEval] Started — pre-worker and post-worker online")

    async def stop(self) -> None:
        self._running = False
        for task in (self._pre_worker_task, self._post_worker_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        logger.info(
            "[DualPassEval] Stopped. Pre: %d evals (%d flagged, %d blocked) | "
            "Post: %d evals (%d flagged, %d blocked)",
            self._pre_total, self._pre_flagged, self._pre_blocked,
            self._post_total, self._post_flagged, self._post_blocked,
        )

    # -- Submission API (non-blocking) ---------------------------------------

    async def submit_pre(
        self,
        context_id: str,
        source_ip: str,
        content: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Submit content for Pass 1 (pre-execution) evaluation."""
        ctx = EvaluationContext(
            context_id=context_id,
            pass_type=EvalPassType.PRE,
            source_ip=source_ip,
            content=content,
            submitted_at=time.monotonic(),
            metadata=metadata or {},
        )
        try:
            self._pre_queue.put_nowait(ctx)
        except asyncio.QueueFull:
            logger.warning("[DualPassEval] Pre-queue full — dropping context_id=%s", context_id)

    async def submit_post(
        self,
        context_id: str,
        source_ip: str,
        content: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Submit content for Pass 2 (post-execution) evaluation."""
        ctx = EvaluationContext(
            context_id=context_id,
            pass_type=EvalPassType.POST,
            source_ip=source_ip,
            content=content,
            submitted_at=time.monotonic(),
            metadata=metadata or {},
        )
        try:
            self._post_queue.put_nowait(ctx)
        except asyncio.QueueFull:
            logger.warning("[DualPassEval] Post-queue full — dropping context_id=%s", context_id)

    # -- Async workers -------------------------------------------------------

    async def _worker_pre(self) -> None:
        logger.debug("[DualPassEval] Pre-execution worker started")
        while self._running:
            try:
                ctx = await asyncio.wait_for(self._pre_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            try:
                result = self._run_pre_pass(ctx)
                self._pre_total += 1
                if result.action == "flag":
                    self._pre_flagged += 1
                elif result.action == "block":
                    self._pre_blocked += 1
                self._history.appendleft(result.to_dict())
                await self._publish_result(result)
            except Exception as exc:
                logger.error("[DualPassEval] Pre-pass error for %s: %s",
                             ctx.context_id, exc, exc_info=True)
            finally:
                self._pre_queue.task_done()

    async def _worker_post(self) -> None:
        logger.debug("[DualPassEval] Post-execution worker started")
        while self._running:
            try:
                ctx = await asyncio.wait_for(self._post_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            try:
                result = self._run_post_pass(ctx)
                self._post_total += 1
                if result.action == "flag":
                    self._post_flagged += 1
                elif result.action == "block":
                    self._post_blocked += 1
                self._history.appendleft(result.to_dict())
                await self._publish_result(result)
            except Exception as exc:
                logger.error("[DualPassEval] Post-pass error for %s: %s",
                             ctx.context_id, exc, exc_info=True)
            finally:
                self._post_queue.task_done()

    # -- Pass implementations ------------------------------------------------

    def _run_pre_pass(self, ctx: EvaluationContext) -> EvaluationResult:
        t0 = time.monotonic()
        flags: list[EvalFlag] = []
        score = 0.0

        for field_path, value in self._iter_fields(ctx.content):
            text = value if isinstance(value, str) else json.dumps(value)

            # Oversized context item
            byte_len = len(text.encode("utf-8", errors="replace"))
            if byte_len > _MAX_CONTEXT_SIZE:
                flags.append(EvalFlag(
                    flag_id=uuid.uuid4().hex[:12],
                    field_path=field_path,
                    rule="oversized_context",
                    description=f"Context item {byte_len:,} B exceeds {_MAX_CONTEXT_SIZE:,} B limit",
                    severity="medium",
                    confidence=0.80,
                    snippet=f"[size={byte_len} bytes]",
                ))
                score += _SEV_SCORE["medium"] * 0.80

            # Pattern matching
            for pattern, desc, conf, sev in _COMPILED_PRE:
                m = pattern.search(text)
                if m:
                    snippet = text[max(0, m.start() - 20):m.end() + 60][:250]
                    flags.append(EvalFlag(
                        flag_id=uuid.uuid4().hex[:12],
                        field_path=field_path,
                        rule=pattern.pattern[:60],
                        description=desc,
                        severity=sev,
                        confidence=conf,
                        snippet=snippet,
                    ))
                    score += _SEV_SCORE.get(sev, 4.0) * conf

        action = self._decide_action(score)
        duration_ms = (time.monotonic() - t0) * 1000.0

        if flags:
            logger.info("[DualPassEval][PRE] ctx=%s ip=%s score=%.1f action=%s flags=%d",
                        ctx.context_id, ctx.source_ip, score, action, len(flags))

        return EvaluationResult(
            context_id=ctx.context_id,
            pass_type=EvalPassType.PRE.value,
            source_ip=ctx.source_ip,
            threat_score=min(100.0, score),
            action=action,
            flags=flags,
            duration_ms=round(duration_ms, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _run_post_pass(self, ctx: EvaluationContext) -> EvaluationResult:
        t0 = time.monotonic()
        flags: list[EvalFlag] = []
        score = 0.0

        for field_path, value in self._iter_fields(ctx.content):
            text = value if isinstance(value, str) else json.dumps(value)

            for pattern, desc, conf, sev in _COMPILED_POST:
                m = pattern.search(text)
                if m:
                    snippet = text[max(0, m.start() - 10):m.end() + 40][:250]
                    flags.append(EvalFlag(
                        flag_id=uuid.uuid4().hex[:12],
                        field_path=field_path,
                        rule=pattern.pattern[:60],
                        description=desc,
                        severity=sev,
                        confidence=conf,
                        snippet=snippet,
                    ))
                    score += _SEV_SCORE.get(sev, 4.0) * conf

        action = self._decide_action(score)
        duration_ms = (time.monotonic() - t0) * 1000.0

        if flags:
            logger.info("[DualPassEval][POST] ctx=%s ip=%s score=%.1f action=%s flags=%d",
                        ctx.context_id, ctx.source_ip, score, action, len(flags))

        return EvaluationResult(
            context_id=ctx.context_id,
            pass_type=EvalPassType.POST.value,
            source_ip=ctx.source_ip,
            threat_score=min(100.0, score),
            action=action,
            flags=flags,
            duration_ms=round(duration_ms, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    # -- Helpers -------------------------------------------------------------

    def _iter_fields(
        self, obj: Any, prefix: str = ""
    ) -> list[tuple[str, Any]]:
        """Flatten a nested dict/list into (dotted.path, leaf_value) pairs."""
        results: list[tuple[str, Any]] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    results.extend(self._iter_fields(v, path))
                else:
                    results.append((path, v))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                path = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    results.extend(self._iter_fields(item, path))
                else:
                    results.append((path, item))
        else:
            results.append((prefix or "__root__", obj))
        return results

    def _decide_action(self, score: float) -> str:
        if score >= BLOCK_THRESHOLD:
            if self._shadow_mode:
                logger.warning(
                    "[DualPassEval][SHADOW] Score %.1f would block — downgraded to 'flag' "
                    "(shadow mode active)", score
                )
                return "flag"
            return "block"
        if score >= FLAG_THRESHOLD:
            return "flag"
        return "allow"

    # -- Publishing ----------------------------------------------------------

    async def _publish_result(self, result: EvaluationResult) -> None:
        if not self._event_bus:
            return

        topic = "eval.pipeline.result"
        if result.action == "block":
            topic = "eval.pipeline.blocked"
        elif result.action == "flag":
            topic = "eval.pipeline.flagged"

        await self._event_bus.publish(Event(
            topic=topic,
            data={
                "context_id": result.context_id,
                "pass_type":  result.pass_type,
                "source_ip":  result.source_ip,
                "threat_score": result.threat_score,
                "action":     result.action,
                "flag_count": len(result.flags),
                "top_severity": max(
                    (f.severity for f in result.flags),
                    key=lambda s: _SEV_SCORE.get(s, 0),
                    default="low",
                ) if result.flags else "none",
            },
        ))

    # -- Stats ---------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "shadow_mode": self._shadow_mode,
            "pre_queue_depth":  self._pre_queue.qsize(),
            "post_queue_depth": self._post_queue.qsize(),
            "pre_total":    self._pre_total,
            "post_total":   self._post_total,
            "pre_flagged":  self._pre_flagged,
            "post_flagged": self._post_flagged,
            "pre_blocked":  self._pre_blocked,
            "post_blocked": self._post_blocked,
        }

    def get_recent(self, limit: int = 50) -> list[dict]:
        return list(self._history)[:limit]
