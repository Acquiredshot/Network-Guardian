# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — MCP/API Protocol Parser

Decodes high-speed semantic network streams, unpacking structured JSON-RPC
messages used in Model Context Protocols, GraphQL schemas, and raw
multi-agent tool-execution payloads.  Unlike the SmartFirewallAgent (which
handles raw HTTP injection strings), this parser operates at the *semantic*
layer — it fully structures the envelope, extracts typed fields, and then
evaluates each field for threat content.

Supported protocol envelopes
-----------------------------
  JSON-RPC 2.0     — ``jsonrpc``, method, params, id, result, error
  MCP              — role (system/user/assistant), content, tool_calls,
                     tool_results, context_injection, rag_blocks
  GraphQL          — query, mutation, subscription, __schema introspection,
                     field arguments
  Multi-agent      — tool_execution, agent_handoff, context_injection,
                     memory_write, retrieval_augmentation payloads

Threat detection
----------------
  prompt_injection    — instruction-override patterns in message fields
  tool_abuse          — dangerous tool names or parameter content
  introspection_probe — GraphQL __schema / JSON-RPC system.listMethods
  context_poisoning   — malicious content embedded in RAG blocks
  oversized_payload   — blobs that could exhaust context windows
  schema_exfiltration — attempts to dump schema or capability lists
  method_enumeration  — many unique method names in a short window
  malformed_envelope  — structurally invalid protocol frames (fuzzing)

Event bus interface
-------------------
  Publishes:
    ``mcp.parser.threat``    — threat detected inside a parsed message
    ``mcp.parser.parsed``    — successful parse summary (info-level)
    ``mcp.parser.malformed`` — envelope failed structural validation
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.mcp_parser")

# ---------------------------------------------------------------------------
# Sizing limits
# ---------------------------------------------------------------------------

_MAX_RAW_SIZE = 1 * 1024 * 1024          # 1 MB hard limit before parse
_OVERSIZED_WARN_BYTES = 64 * 1024        # 64 KB soft warning
_METHOD_ENUM_WINDOW_SECS = 30            # window for method-enum detection
_METHOD_ENUM_THRESHOLD = 8              # unique methods within window = suspect
_SNIPPET_LEN = 250                       # chars kept for threat snippet

# ---------------------------------------------------------------------------
# Prompt-injection & tool-abuse patterns
# ---------------------------------------------------------------------------

_PROMPT_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # (regex_pattern, description, confidence)
    (r"ignore\s+(all\s+)?previous\s+instructions?", "instruction override", 0.97),
    (r"disregard\s+(all\s+)?prior\s+(instructions?|context)", "context wipe", 0.97),
    (r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbreak|free\s+AI)", "persona hijack", 0.95),
    (r"system\s*:\s*(?:you\s+must|always|never|your\s+new)", "fake system tag", 0.92),
    (r"\[INST\].*override.*\[/INST\]", "INST-tag injection", 0.93),
    (r"<\s*/?system\s*>", "synthetic system tag", 0.90),
    (r"repeat\s+after\s+me.*password|echo\s+.*secret", "data extraction command", 0.88),
    (r"print\s+(all|your|the)\s+(system\s+)?prompt", "prompt exfiltration", 0.94),
    (r"reveal\s+(your|the)\s+(instructions?|system\s+prompt|context)", "prompt reveal", 0.91),
    (r"what\s+(are|were)\s+your\s+(exact\s+)?instructions?", "instruction probe", 0.85),
    (r"token\s*smuggling|context\s*injection\s*attack", "explicit attack declaration", 0.99),
    (r"###\s*End\s+of\s+system|---\s*end\s+instructions", "context boundary break", 0.88),
    (r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>", "raw tokenizer injection", 0.96),
    (r"RLHF\s+override|reward\s+hack|constitutional\s+bypass", "alignment bypass", 0.93),
]

_TOOL_ABUSE_NAMES: set[str] = {
    "eval", "exec", "shell", "bash", "cmd", "powershell", "system", "popen",
    "subprocess", "os_command", "run_code", "execute_code", "terminal",
    "file_write", "file_delete", "file_exec", "spawn_process", "kernel_call",
    "network_send", "exfiltrate", "upload_data", "send_payload",
}

_INTROSPECTION_PATTERNS: list[tuple[str, str, float]] = [
    (r"__schema\s*\{", "GraphQL schema introspection", 0.95),
    (r"__type\s*\(", "GraphQL type introspection", 0.92),
    (r"IntrospectionQuery", "named introspection query", 0.97),
    (r"system\.listMethods|system\.methodHelp|system\.methodSignature",
     "XML-RPC/JSON-RPC introspection", 0.95),
    (r"rpc\.discover|openrpc\.discover", "OpenRPC schema discovery", 0.93),
    (r"schema\s+inspection|enumerate\s+tools|list\s+available\s+tools",
     "capability enumeration", 0.88),
]

_EXFILTRATION_PATTERNS: list[tuple[str, str, float]] = [
    (r"[A-Za-z0-9+/]{40,}={0,2}", "long base64 blob", 0.60),
    (r"(AKIA|ASIA)[A-Z0-9]{16}", "AWS access key", 0.98),
    (r"sk-[A-Za-z0-9]{32,}", "API secret key", 0.96),
    (r"['\"]password['\"]\s*:\s*['\"][^'\"]{6,}", "password field in response", 0.85),
    (r"BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY", "private key material", 0.99),
    (r"token\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}", "auth token in response", 0.82),
]

# Pre-compiled pattern registry
_COMPILED_INJECTION = [(re.compile(p, re.IGNORECASE), d, c) for p, d, c in _PROMPT_INJECTION_PATTERNS]
_COMPILED_INTROSPECTION = [(re.compile(p, re.IGNORECASE), d, c) for p, d, c in _INTROSPECTION_PATTERNS]
_COMPILED_EXFILTRATION = [(re.compile(p, re.IGNORECASE), d, c) for p, d, c in _EXFILTRATION_PATTERNS]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class ProtocolType(str, Enum):
    JSONRPC    = "jsonrpc"
    MCP        = "mcp"
    GRAPHQL    = "graphql"
    MULTIAGENT = "multiagent"
    UNKNOWN    = "unknown"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION   = "prompt_injection"
    TOOL_ABUSE         = "tool_abuse"
    INTROSPECTION      = "introspection_probe"
    CONTEXT_POISONING  = "context_poisoning"
    OVERSIZED_PAYLOAD  = "oversized_payload"
    SCHEMA_EXFIL       = "schema_exfiltration"
    METHOD_ENUM        = "method_enumeration"
    MALFORMED          = "malformed_envelope"
    EXFILTRATION       = "data_exfiltration"


@dataclass
class ThreatIndicator:
    indicator_id: str
    category: ThreatCategory
    field_path: str
    snippet: str
    severity: str        # critical | high | medium | low
    confidence: float
    description: str
    rule_name: str


@dataclass
class ParsedMessage:
    message_id: str
    protocol: ProtocolType
    source_ip: str
    raw_size: int
    timestamp: str
    fields: dict[str, Any]
    threats: list[ThreatIndicator]
    threat_score: float  # 0–100
    action_taken: str    # allow | flag | block

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["protocol"] = self.protocol.value
        d["threats"] = [
            {**asdict(t), "category": t.category.value}
            for t in self.threats
        ]
        return d


# ---------------------------------------------------------------------------
# Severity → score mapping
# ---------------------------------------------------------------------------

_SEV_SCORE: dict[str, float] = {
    "critical": 40.0,
    "high":     20.0,
    "medium":   10.0,
    "low":       4.0,
}


def _classify_severity(confidence: float, base_severity: str = "medium") -> str:
    if confidence >= 0.95:
        return "critical"
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.70:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# MCPProtocolParser
# ---------------------------------------------------------------------------

class MCPProtocolParser:
    """
    High-speed semantic network stream parser.

    Usage::

        parser = MCPProtocolParser(event_bus=engine.event_bus)
        parser.start()
        result = await parser.parse_stream(raw_data, source_ip="10.0.0.5")
    """

    def __init__(self, event_bus: "EventBus | None" = None) -> None:
        self._event_bus = event_bus
        self._running = False

        # Stats
        self._total_parsed = 0
        self._total_threats = 0
        self._total_blocked = 0
        self._total_malformed = 0

        # Per-IP method enumeration tracking: ip → deque of (timestamp, method)
        self._method_log: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # Recent parse history for dashboard
        self._history: deque[dict] = deque(maxlen=500)

    # -- Lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self._running = True
        logger.info("[MCPParser] Started — monitoring JSON-RPC / MCP / GraphQL / multi-agent streams")

    def stop(self) -> None:
        self._running = False
        logger.info("[MCPParser] Stopped. Parsed=%d Threats=%d Blocked=%d",
                    self._total_parsed, self._total_threats, self._total_blocked)

    # -- Public API ----------------------------------------------------------

    async def parse_stream(self, data: str | bytes, source_ip: str = "0.0.0.0") -> ParsedMessage:
        """Parse a raw network payload and evaluate it for semantic threats."""
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8", errors="replace")
            except Exception:
                data = str(data)

        raw_size = len(data)

        # Hard size limit
        if raw_size > _MAX_RAW_SIZE:
            return await self._make_malformed(
                source_ip, raw_size, "payload exceeds 1 MB hard limit"
            )

        protocol = self._detect_protocol(data)

        try:
            if protocol == ProtocolType.JSONRPC:
                msg = self._parse_jsonrpc(json.loads(data), source_ip, raw_size)
            elif protocol == ProtocolType.MCP:
                msg = self._parse_mcp(json.loads(data), source_ip, raw_size)
            elif protocol == ProtocolType.GRAPHQL:
                msg = self._parse_graphql(data, source_ip, raw_size)
            elif protocol == ProtocolType.MULTIAGENT:
                msg = self._parse_multiagent(json.loads(data), source_ip, raw_size)
            else:
                msg = self._parse_unknown(data, source_ip, raw_size)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            return await self._make_malformed(source_ip, raw_size, str(exc))

        # Soft size warning
        if raw_size > _OVERSIZED_WARN_BYTES and not any(
            t.category == ThreatCategory.OVERSIZED_PAYLOAD for t in msg.threats
        ):
            msg.threats.append(ThreatIndicator(
                indicator_id=uuid.uuid4().hex[:12],
                category=ThreatCategory.OVERSIZED_PAYLOAD,
                field_path="__envelope__",
                snippet=f"size={raw_size} bytes",
                severity="medium",
                confidence=0.75,
                description=f"Payload size {raw_size:,} B exceeds soft limit {_OVERSIZED_WARN_BYTES:,} B",
                rule_name="oversized_payload",
            ))
            msg.threat_score = min(100.0, msg.threat_score + _SEV_SCORE["medium"])

        # Determine action
        msg.action_taken = self._decide_action(msg.threat_score)

        self._total_parsed += 1
        if msg.threats:
            self._total_threats += len(msg.threats)
        if msg.action_taken == "block":
            self._total_blocked += 1

        self._history.appendleft(msg.to_dict())
        await self._publish(msg)
        return msg

    # -- Protocol detection --------------------------------------------------

    def _detect_protocol(self, data: str) -> ProtocolType:
        stripped = data.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            if re.search(r"\b(query|mutation|subscription)\s*\{", stripped, re.IGNORECASE):
                return ProtocolType.GRAPHQL
            return ProtocolType.UNKNOWN

        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return ProtocolType.UNKNOWN

        if isinstance(parsed, dict):
            if "jsonrpc" in parsed:
                return ProtocolType.JSONRPC
            if "query" in parsed and isinstance(parsed["query"], str):
                return ProtocolType.GRAPHQL
            if parsed.get("type") in {
                "tool_call", "tool_result", "system", "user", "assistant",
                "context_injection", "rag_block",
            }:
                return ProtocolType.MCP
            if any(k in parsed for k in ("tool_execution", "agent_handoff",
                                          "memory_write", "retrieval_augmentation")):
                return ProtocolType.MULTIAGENT

        return ProtocolType.UNKNOWN

    # -- Per-protocol parsers ------------------------------------------------

    def _parse_jsonrpc(self, obj: dict, source_ip: str, raw_size: int) -> ParsedMessage:
        threats: list[ThreatIndicator] = []
        score = 0.0
        now = datetime.now(timezone.utc).isoformat()

        method = obj.get("method", "")
        params = obj.get("params", {})
        result = obj.get("result", None)
        error  = obj.get("error", None)

        fields = {
            "method": method,
            "params": params,
            "id": obj.get("id"),
            "result": result,
            "error": error,
        }

        # Method enumeration tracking
        if method:
            ts = time.monotonic()
            log = self._method_log[source_ip]
            log.append((ts, method))
            # Prune old entries
            cutoff = ts - _METHOD_ENUM_WINDOW_SECS
            while log and log[0][0] < cutoff:
                log.popleft()
            unique_methods = len({m for _, m in log})
            if unique_methods >= _METHOD_ENUM_THRESHOLD:
                ind = ThreatIndicator(
                    indicator_id=uuid.uuid4().hex[:12],
                    category=ThreatCategory.METHOD_ENUM,
                    field_path="method",
                    snippet=method[:_SNIPPET_LEN],
                    severity="high",
                    confidence=0.88,
                    description=f"{unique_methods} unique methods in {_METHOD_ENUM_WINDOW_SECS}s window",
                    rule_name="method_enumeration",
                )
                threats.append(ind)
                score += _SEV_SCORE["high"]

        # Introspection check on method name
        for pattern, desc, conf in _COMPILED_INTROSPECTION:
            if pattern.search(method):
                threats.append(ThreatIndicator(
                    indicator_id=uuid.uuid4().hex[:12],
                    category=ThreatCategory.INTROSPECTION,
                    field_path="method",
                    snippet=method[:_SNIPPET_LEN],
                    severity=_classify_severity(conf),
                    confidence=conf,
                    description=desc,
                    rule_name=pattern.pattern[:60],
                ))
                score += _SEV_SCORE[_classify_severity(conf)] * conf

        # Scan params for injection
        params_str = json.dumps(params) if not isinstance(params, str) else params
        ind_list = self._evaluate_text("params", params_str)
        threats.extend(ind_list)
        score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        # Scan result for exfiltration
        if result is not None:
            result_str = json.dumps(result) if not isinstance(result, str) else result
            ind_list = self._scan_exfiltration("result", result_str)
            threats.extend(ind_list)
            score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        return ParsedMessage(
            message_id=uuid.uuid4().hex[:16],
            protocol=ProtocolType.JSONRPC,
            source_ip=source_ip,
            raw_size=raw_size,
            timestamp=now,
            fields=fields,
            threats=threats,
            threat_score=min(100.0, score),
            action_taken="allow",
        )

    def _parse_mcp(self, obj: dict, source_ip: str, raw_size: int) -> ParsedMessage:
        threats: list[ThreatIndicator] = []
        score = 0.0
        now = datetime.now(timezone.utc).isoformat()

        msg_type = obj.get("type", "unknown")
        role = obj.get("role", "")
        content = obj.get("content", "")
        tool_calls = obj.get("tool_calls", [])
        tool_results = obj.get("tool_results", [])
        rag_blocks = obj.get("rag_blocks", [])
        context_items = obj.get("context_injection", [])

        fields = {
            "type": msg_type,
            "role": role,
            "content_len": len(str(content)),
            "tool_calls": len(tool_calls),
            "tool_results": len(tool_results),
            "rag_blocks": len(rag_blocks),
        }

        # Evaluate content text (system/user fields most dangerous for injection)
        content_str = content if isinstance(content, str) else json.dumps(content)
        is_system = (role == "system" or msg_type == "system")
        ind_list = self._evaluate_text("content", content_str,
                                       boost=1.5 if is_system else 1.0)
        threats.extend(ind_list)
        score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        # Evaluate each tool call
        for i, tc in enumerate(tool_calls if isinstance(tool_calls, list) else []):
            tool_name = str(tc.get("name", tc.get("function", {}).get("name", ""))).lower()
            if tool_name in _TOOL_ABUSE_NAMES:
                threats.append(ThreatIndicator(
                    indicator_id=uuid.uuid4().hex[:12],
                    category=ThreatCategory.TOOL_ABUSE,
                    field_path=f"tool_calls[{i}].name",
                    snippet=tool_name[:_SNIPPET_LEN],
                    severity="critical",
                    confidence=0.95,
                    description=f"Dangerous tool invocation: '{tool_name}'",
                    rule_name="tool_abuse_name",
                ))
                score += _SEV_SCORE["critical"] * 0.95

            params_str = json.dumps(tc.get("parameters", tc.get("arguments", {})))
            ind_list = self._evaluate_text(f"tool_calls[{i}].params", params_str)
            threats.extend(ind_list)
            score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        # Evaluate each RAG block for context poisoning
        for i, block in enumerate(rag_blocks if isinstance(rag_blocks, list) else []):
            block_text = block if isinstance(block, str) else json.dumps(block)
            ind_list = self._evaluate_text(f"rag_blocks[{i}]", block_text)
            for ind in ind_list:
                ind.category = ThreatCategory.CONTEXT_POISONING
            threats.extend(ind_list)
            score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        # Evaluate tool results for exfiltration
        for i, tr in enumerate(tool_results if isinstance(tool_results, list) else []):
            result_str = tr if isinstance(tr, str) else json.dumps(tr)
            ind_list = self._scan_exfiltration(f"tool_results[{i}]", result_str)
            threats.extend(ind_list)
            score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        # Evaluate context injection items
        for i, item in enumerate(context_items if isinstance(context_items, list) else []):
            item_str = item if isinstance(item, str) else json.dumps(item)
            ind_list = self._evaluate_text(f"context_injection[{i}]", item_str)
            threats.extend(ind_list)
            score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        return ParsedMessage(
            message_id=uuid.uuid4().hex[:16],
            protocol=ProtocolType.MCP,
            source_ip=source_ip,
            raw_size=raw_size,
            timestamp=now,
            fields=fields,
            threats=threats,
            threat_score=min(100.0, score),
            action_taken="allow",
        )

    def _parse_graphql(self, data: str, source_ip: str, raw_size: int) -> ParsedMessage:
        threats: list[ThreatIndicator] = []
        score = 0.0
        now = datetime.now(timezone.utc).isoformat()

        # Try JSON wrapper first
        query_text = data
        variables: dict = {}
        operation_name = ""
        try:
            obj = json.loads(data)
            query_text = obj.get("query", data)
            variables = obj.get("variables", {})
            operation_name = obj.get("operationName", "")
        except json.JSONDecodeError:
            pass

        op_match = re.search(r"^\s*(query|mutation|subscription)", query_text, re.IGNORECASE)
        operation_type = op_match.group(1).lower() if op_match else "unknown"

        fields = {
            "operation_type": operation_type,
            "operation_name": operation_name,
            "query_len": len(query_text),
            "variable_count": len(variables),
        }

        # Introspection check
        for pattern, desc, conf in _COMPILED_INTROSPECTION:
            if pattern.search(query_text):
                threats.append(ThreatIndicator(
                    indicator_id=uuid.uuid4().hex[:12],
                    category=ThreatCategory.INTROSPECTION,
                    field_path="query",
                    snippet=query_text[:_SNIPPET_LEN],
                    severity=_classify_severity(conf),
                    confidence=conf,
                    description=desc,
                    rule_name=pattern.pattern[:60],
                ))
                score += _SEV_SCORE[_classify_severity(conf)] * conf

        # Injection in query text or variables
        ind_list = self._evaluate_text("query", query_text)
        threats.extend(ind_list)
        score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        vars_str = json.dumps(variables)
        ind_list = self._evaluate_text("variables", vars_str)
        threats.extend(ind_list)
        score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        # Deeply-nested query (DoS via complexity)
        depth = query_text.count("{")
        if depth > 15:
            threats.append(ThreatIndicator(
                indicator_id=uuid.uuid4().hex[:12],
                category=ThreatCategory.OVERSIZED_PAYLOAD,
                field_path="query",
                snippet=f"nesting depth ≈ {depth}",
                severity="high" if depth > 30 else "medium",
                confidence=0.80,
                description=f"GraphQL query nesting depth {depth} may cause resolver DoS",
                rule_name="graphql_deep_nesting",
            ))
            score += _SEV_SCORE["high" if depth > 30 else "medium"] * 0.80

        return ParsedMessage(
            message_id=uuid.uuid4().hex[:16],
            protocol=ProtocolType.GRAPHQL,
            source_ip=source_ip,
            raw_size=raw_size,
            timestamp=now,
            fields=fields,
            threats=threats,
            threat_score=min(100.0, score),
            action_taken="allow",
        )

    def _parse_multiagent(self, obj: dict, source_ip: str, raw_size: int) -> ParsedMessage:
        threats: list[ThreatIndicator] = []
        score = 0.0
        now = datetime.now(timezone.utc).isoformat()

        action_type = next((k for k in obj if k in (
            "tool_execution", "agent_handoff", "memory_write",
            "retrieval_augmentation", "context_injection",
        )), "unknown")

        agent_id = obj.get("agent_id", obj.get("from_agent", ""))
        payload = obj.get("payload", obj.get("data", obj.get("content", "")))
        tool_name = str(obj.get("tool_name", obj.get("function", ""))).lower()

        fields = {
            "action_type": action_type,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "payload_len": len(str(payload)),
        }

        # Tool abuse check
        if tool_name in _TOOL_ABUSE_NAMES:
            threats.append(ThreatIndicator(
                indicator_id=uuid.uuid4().hex[:12],
                category=ThreatCategory.TOOL_ABUSE,
                field_path="tool_name",
                snippet=tool_name[:_SNIPPET_LEN],
                severity="critical",
                confidence=0.95,
                description=f"Multi-agent dangerous tool invocation: '{tool_name}'",
                rule_name="multiagent_tool_abuse",
            ))
            score += _SEV_SCORE["critical"] * 0.95

        # Payload scan
        payload_str = payload if isinstance(payload, str) else json.dumps(payload)
        ind_list = self._evaluate_text("payload", payload_str)
        threats.extend(ind_list)
        score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        # Exfiltration in memory_write or retrieval
        if action_type in ("memory_write", "retrieval_augmentation"):
            ind_list = self._scan_exfiltration(action_type, payload_str)
            threats.extend(ind_list)
            score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        return ParsedMessage(
            message_id=uuid.uuid4().hex[:16],
            protocol=ProtocolType.MULTIAGENT,
            source_ip=source_ip,
            raw_size=raw_size,
            timestamp=now,
            fields=fields,
            threats=threats,
            threat_score=min(100.0, score),
            action_taken="allow",
        )

    def _parse_unknown(self, data: str, source_ip: str, raw_size: int) -> ParsedMessage:
        threats: list[ThreatIndicator] = []
        score = 0.0
        now = datetime.now(timezone.utc).isoformat()

        ind_list = self._evaluate_text("raw_body", data[:4096])
        threats.extend(ind_list)
        score += sum(_SEV_SCORE.get(t.severity, 4.0) * t.confidence for t in ind_list)

        return ParsedMessage(
            message_id=uuid.uuid4().hex[:16],
            protocol=ProtocolType.UNKNOWN,
            source_ip=source_ip,
            raw_size=raw_size,
            timestamp=now,
            fields={"preview": data[:200]},
            threats=threats,
            threat_score=min(100.0, score),
            action_taken="allow",
        )

    # -- Field evaluation helpers --------------------------------------------

    def _evaluate_text(
        self, field_path: str, text: str, boost: float = 1.0
    ) -> list[ThreatIndicator]:
        """Scan text for prompt-injection and introspection patterns."""
        indicators: list[ThreatIndicator] = []
        if not text:
            return indicators

        for pattern, desc, conf in _COMPILED_INJECTION:
            m = pattern.search(text)
            if m:
                sev = _classify_severity(conf * boost)
                indicators.append(ThreatIndicator(
                    indicator_id=uuid.uuid4().hex[:12],
                    category=ThreatCategory.PROMPT_INJECTION,
                    field_path=field_path,
                    snippet=text[max(0, m.start() - 20):m.end() + 60][:_SNIPPET_LEN],
                    severity=sev,
                    confidence=min(1.0, conf * boost),
                    description=desc,
                    rule_name=pattern.pattern[:60],
                ))

        for pattern, desc, conf in _COMPILED_INTROSPECTION:
            m = pattern.search(text)
            if m:
                indicators.append(ThreatIndicator(
                    indicator_id=uuid.uuid4().hex[:12],
                    category=ThreatCategory.INTROSPECTION,
                    field_path=field_path,
                    snippet=text[max(0, m.start() - 10):m.end() + 80][:_SNIPPET_LEN],
                    severity=_classify_severity(conf),
                    confidence=conf,
                    description=desc,
                    rule_name=pattern.pattern[:60],
                ))

        return indicators

    def _scan_exfiltration(self, field_path: str, text: str) -> list[ThreatIndicator]:
        """Scan text for data exfiltration patterns."""
        indicators: list[ThreatIndicator] = []
        if not text:
            return indicators

        for pattern, desc, conf in _COMPILED_EXFILTRATION:
            m = pattern.search(text)
            if m:
                indicators.append(ThreatIndicator(
                    indicator_id=uuid.uuid4().hex[:12],
                    category=ThreatCategory.EXFILTRATION,
                    field_path=field_path,
                    snippet=text[max(0, m.start() - 5):m.end() + 20][:_SNIPPET_LEN],
                    severity=_classify_severity(conf),
                    confidence=conf,
                    description=desc,
                    rule_name=pattern.pattern[:60],
                ))

        return indicators

    # -- Action decision -----------------------------------------------------

    def _decide_action(self, score: float) -> str:
        if score >= 60.0:
            return "block"
        if score >= 25.0:
            return "flag"
        return "allow"

    # -- Malformed helper ----------------------------------------------------

    async def _make_malformed(
        self, source_ip: str, raw_size: int, reason: str
    ) -> ParsedMessage:
        self._total_malformed += 1
        now = datetime.now(timezone.utc).isoformat()
        msg = ParsedMessage(
            message_id=uuid.uuid4().hex[:16],
            protocol=ProtocolType.UNKNOWN,
            source_ip=source_ip,
            raw_size=raw_size,
            timestamp=now,
            fields={"error": reason},
            threats=[ThreatIndicator(
                indicator_id=uuid.uuid4().hex[:12],
                category=ThreatCategory.MALFORMED,
                field_path="__envelope__",
                snippet=reason[:_SNIPPET_LEN],
                severity="low",
                confidence=0.70,
                description=f"Malformed protocol envelope: {reason}",
                rule_name="malformed_envelope",
            )],
            threat_score=8.0,
            action_taken="flag",
        )
        if self._event_bus:
            await self._event_bus.publish(Event(
                topic="mcp.parser.malformed",
                data={"source_ip": source_ip, "reason": reason, "size": raw_size},
            ))
        return msg

    # -- Event publishing ----------------------------------------------------

    async def _publish(self, msg: ParsedMessage) -> None:
        if not self._event_bus:
            return

        if msg.threats:
            await self._event_bus.publish(Event(
                topic="mcp.parser.threat",
                data={
                    "message_id": msg.message_id,
                    "protocol": msg.protocol.value,
                    "source_ip": msg.source_ip,
                    "threat_score": msg.threat_score,
                    "action_taken": msg.action_taken,
                    "threat_count": len(msg.threats),
                    "categories": list({t.category.value for t in msg.threats}),
                    "top_severity": max((t.severity for t in msg.threats),
                                        key=lambda s: _SEV_SCORE.get(s, 0), default="low"),
                },
            ))
        else:
            await self._event_bus.publish(Event(
                topic="mcp.parser.parsed",
                data={
                    "message_id": msg.message_id,
                    "protocol": msg.protocol.value,
                    "source_ip": msg.source_ip,
                    "raw_size": msg.raw_size,
                    "action_taken": msg.action_taken,
                },
            ))

    # -- Stats ---------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "total_parsed": self._total_parsed,
            "total_threats": self._total_threats,
            "total_blocked": self._total_blocked,
            "total_malformed": self._total_malformed,
            "recent_count": len(self._history),
        }

    def get_recent(self, limit: int = 50) -> list[dict]:
        return list(self._history)[:limit]
