# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
LangGraph + DeepSeek Reasoner for Network Guardian
====================================================

Replaces the keyword-based intent classification and plan-building in
``TriageAgent`` with a proper LangGraph state machine where each node is a
discrete processing step and DeepSeek-R1 (``deepseek-reasoner``) provides
deep chain-of-thought threat reasoning at the REASON node.

Graph topology
--------------
  [ingest] → [reason] → [plan] → [summarize]
                 ↑         |
                 └─────────┘  (re-reason if confidence < 0.5)

State fields (``NetworkGuardianState``)
---------------------------------------
  intent              : str      – free-text user goal
  system_state        : dict     – live snapshot from TriageAgent.SystemState
  observations        : dict     – threat observations from sub-agents
  deepseek_reasoning  : str      – raw DeepSeek chain-of-thought
  intent_class        : str      – classified intent (THREAT_HUNT, etc.)
  confidence          : float    – classification confidence 0–1
  action_plan         : list     – ordered GoalStep-like dicts
  findings            : list     – aggregated finding dicts
  recommendations     : list     – prioritised fix strings
  messages            : list     – LangChain message history
  error               : str      – last error, empty on success
  iteration           : int      – re-reason guard counter

Environment variables
---------------------
  DEEPSEEK_API_KEY        – DeepSeek API key (required for LLM nodes)
  DEEPSEEK_MODEL          – override model, default ``deepseek-reasoner``
  DEEPSEEK_BASE_URL       – override endpoint, default ``https://api.deepseek.com``
  DEEPSEEK_TIMEOUT        – request timeout seconds, default 60
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Literal, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph

logger = logging.getLogger("network_guardian.ai.langgraph_reasoner")

# ---------------------------------------------------------------------------
# DeepSeek client factory
# ---------------------------------------------------------------------------

_DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
_DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-reasoner")
_DEEPSEEK_TIMEOUT = int(os.getenv("DEEPSEEK_TIMEOUT", "60"))

_SYSTEM_PROMPT = """You are the Reasoning Engine for Network Guardian, an enterprise-grade
network security platform. Your role is to:

1. Analyse the user's security intent and the current system state.
2. Classify the intent into exactly ONE of these categories:
   THREAT_RESPONSE | THREAT_HUNT | NETWORK_OPS | SYSTEM_AUDIT |
   CLOAKING_OPS | REPORT_GEN | AGENT_CTRL | STATUS_QUERY | UNKNOWN
3. Build a prioritised action plan using the available sub-agents:
   smart_firewall | malware_scanner | ids | ips | auditor |
   web_browsing | cloaking | wifi_stealth | system_state | agent_ctrl
4. Provide security recommendations grounded in MITRE ATT&CK and NIST SP 800-53.

Respond **only** with valid JSON in the following schema (no markdown fences):
{
  "intent_class": "<one of the above>",
  "confidence": <0.0–1.0>,
  "reasoning_summary": "<2-4 sentence plain-English reasoning>",
  "action_plan": [
    {"agent": "<agent_key>", "action": "<description>", "kwargs": {}},
    ...
  ],
  "recommendations": ["<rec1>", "<rec2>", ...]
}"""


def _make_llm(api_key: str | None = None) -> ChatOpenAI:
    """Instantiate the DeepSeek ChatOpenAI client."""
    key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
    return ChatOpenAI(
        model=_DEEPSEEK_MODEL,
        api_key=key or "no-key",  # allow offline/mock mode
        base_url=_DEEPSEEK_BASE_URL,
        timeout=_DEEPSEEK_TIMEOUT,
        max_retries=1,
        temperature=0.0,
    )


# ---------------------------------------------------------------------------
# State definition
# ---------------------------------------------------------------------------


class NetworkGuardianState(TypedDict, total=False):
    """Full mutable state that flows through the LangGraph nodes."""

    # Input fields
    intent: str
    system_state: dict
    observations: dict
    api_key: str  # optional per-call override

    # Reasoning outputs
    deepseek_reasoning: str
    intent_class: str
    confidence: float

    # Plan + outcomes
    action_plan: list[dict]
    findings: list[dict]
    recommendations: list[str]

    # LangChain message history
    messages: list

    # Control
    error: str
    iteration: int


# ---------------------------------------------------------------------------
# Node: ingest
# ---------------------------------------------------------------------------


def ingest_node(state: NetworkGuardianState) -> NetworkGuardianState:
    """Validate inputs and prepare the message history for the REASON node."""
    intent = state.get("intent", "").strip()
    if not intent:
        return {**state, "error": "No intent provided", "intent_class": "UNKNOWN", "confidence": 0.0}

    system_state = state.get("system_state", {})
    observations = state.get("observations", {})

    # Truncate large observations to keep the context window manageable
    obs_summary: dict[str, Any] = {
        "threat_level": system_state.get("threat_level", "unknown"),
        "active_threat_count": len(system_state.get("active_threats", [])),
        "blocked_ip_count": len(system_state.get("blocked_ips", [])),
        "agent_statuses": system_state.get("agent_statuses", {}),
        "recent_findings_count": len(observations.get("findings", [])),
    }

    # Add first 5 findings for context
    findings_preview = observations.get("findings", [])[:5]
    if findings_preview:
        obs_summary["findings_preview"] = findings_preview

    human_content = (
        f"User intent: {intent}\n\n"
        f"Current system state:\n{json.dumps(obs_summary, indent=2)}"
    )

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=human_content),
    ]

    logger.debug("[INGEST] Prepared %d messages for reasoning. Intent: %r", len(messages), intent)
    return {
        **state,
        "messages": messages,
        "error": "",
        "iteration": state.get("iteration", 0),
    }


# ---------------------------------------------------------------------------
# Node: reason (DeepSeek)
# ---------------------------------------------------------------------------


def reason_node(state: NetworkGuardianState) -> NetworkGuardianState:
    """Call DeepSeek-R1 to reason about the intent and current threat posture."""
    if state.get("error"):
        return state  # propagate upstream error without calling LLM

    api_key = state.get("api_key") or os.getenv("DEEPSEEK_API_KEY", "")
    iteration = state.get("iteration", 0)

    if not api_key:
        logger.warning("[REASON] No DEEPSEEK_API_KEY — falling back to keyword classification")
        return {**state, "deepseek_reasoning": "(no API key — keyword fallback)", "error": "no_api_key"}

    llm = _make_llm(api_key=api_key)
    messages = state.get("messages", [])

    try:
        response: AIMessage = llm.invoke(messages)
        raw = response.content or ""

        # DeepSeek-R1 returns <think>...</think> before the final answer
        think_match = re.search(r"<think>(.*?)</think>", raw, re.DOTALL)
        chain_of_thought = think_match.group(1).strip() if think_match else ""
        # Strip the think block from the answer part
        answer = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

        # Parse JSON answer
        try:
            parsed = json.loads(answer)
        except json.JSONDecodeError:
            # Try extracting JSON from inside a markdown code block
            json_match = re.search(r"```(?:json)?\s*([\s\S]+?)```", answer)
            if json_match:
                parsed = json.loads(json_match.group(1))
            else:
                raise ValueError(f"Could not parse JSON from DeepSeek response: {answer[:300]}")

        intent_class = parsed.get("intent_class", "UNKNOWN").upper()
        confidence = float(parsed.get("confidence", 0.5))
        reasoning_summary = parsed.get("reasoning_summary", "")
        action_plan = parsed.get("action_plan", [])
        recommendations = parsed.get("recommendations", [])

        full_reasoning = (
            f"[Chain of Thought]\n{chain_of_thought}\n\n[Summary]\n{reasoning_summary}"
            if chain_of_thought else reasoning_summary
        )

        logger.info(
            "[REASON] DeepSeek classified intent=%s (confidence=%.1f%%) | "
            "%d steps planned | iteration=%d",
            intent_class, confidence * 100, len(action_plan), iteration,
        )

        return {
            **state,
            "deepseek_reasoning": full_reasoning,
            "intent_class": intent_class,
            "confidence": confidence,
            "action_plan": action_plan,
            "recommendations": recommendations,
            "messages": messages + [response],
            "error": "",
        }

    except Exception as exc:
        logger.error("[REASON] DeepSeek call failed (iteration=%d): %s", iteration, exc)
        return {
            **state,
            "deepseek_reasoning": "",
            "error": str(exc),
            "iteration": iteration + 1,
        }


# ---------------------------------------------------------------------------
# Node: plan
# ---------------------------------------------------------------------------


def plan_node(state: NetworkGuardianState) -> NetworkGuardianState:
    """Validate / enrich the action plan produced by the reason node.

    If DeepSeek returned an empty plan or errored, build a sensible
    fallback plan using the intent class so the system keeps running.
    """
    action_plan = state.get("action_plan", [])
    intent_class = state.get("intent_class", "UNKNOWN")

    if not action_plan:
        # Fallback plans by intent class
        _fallback: dict[str, list[dict]] = {
            "THREAT_RESPONSE": [
                {"agent": "smart_firewall", "action": "Pull firewall threat statistics", "kwargs": {}},
                {"agent": "malware_scanner", "action": "Malware process scan", "kwargs": {}},
            ],
            "THREAT_HUNT": [
                {"agent": "malware_scanner", "action": "Full malware process scan", "kwargs": {}},
                {"agent": "ids", "action": "Recent IDS alert summary", "kwargs": {}},
            ],
            "SYSTEM_AUDIT": [
                {"agent": "malware_scanner", "action": "Malware scan — audit baseline", "kwargs": {}},
                {"agent": "smart_firewall", "action": "Firewall rule audit", "kwargs": {}},
                {"agent": "ids", "action": "IDS alert history review", "kwargs": {}},
            ],
            "STATUS_QUERY": [
                {"agent": "system_state", "action": "System state snapshot", "kwargs": {}},
            ],
        }
        action_plan = _fallback.get(intent_class, [
            {"agent": "system_state", "action": "System state snapshot", "kwargs": {}},
        ])
        logger.info("[PLAN] Used fallback plan for intent_class=%s (%d steps)", intent_class, len(action_plan))
    else:
        # Validate each step has required fields
        validated: list[dict] = []
        for step in action_plan:
            if isinstance(step, dict) and step.get("agent") and step.get("action"):
                validated.append({
                    "agent": step["agent"],
                    "action": step["action"],
                    "kwargs": step.get("kwargs", {}),
                })
        action_plan = validated or action_plan

    return {**state, "action_plan": action_plan}


# ---------------------------------------------------------------------------
# Node: summarize
# ---------------------------------------------------------------------------


def summarize_node(state: NetworkGuardianState) -> NetworkGuardianState:
    """Compile final findings + recommendations for the caller."""
    intent_class = state.get("intent_class", "UNKNOWN")
    confidence = state.get("confidence", 0.0)
    reasoning = state.get("deepseek_reasoning", "")
    action_plan = state.get("action_plan", [])
    recs = state.get("recommendations", [])

    logger.info(
        "[SUMMARIZE] intent=%s confidence=%.1f%% plan=%d steps recs=%d",
        intent_class, confidence * 100, len(action_plan), len(recs),
    )

    # Attach reasoning as a meta finding if DeepSeek was used
    findings = list(state.get("findings", []))
    if reasoning and "(no API key" not in reasoning:
        findings.insert(0, {
            "source": "deepseek_reasoner",
            "type": "ai_reasoning",
            "intent_class": intent_class,
            "confidence": confidence,
            "summary": reasoning[:2000],  # cap length for storage
        })

    return {**state, "findings": findings}


# ---------------------------------------------------------------------------
# Edge condition: should we re-reason?
# ---------------------------------------------------------------------------


def _should_re_reason(state: NetworkGuardianState) -> Literal["reason", "plan"]:
    """Re-run the reason node if confidence is low and we haven't looped yet."""
    confidence = state.get("confidence", 1.0)
    iteration = state.get("iteration", 0)
    error = state.get("error", "")

    if error == "no_api_key":
        # Skip re-reason loop when there's no key
        return "plan"
    if confidence < 0.40 and iteration < 1:
        logger.info("[EDGE] Low confidence (%.1f%%) — re-running reason node", confidence * 100)
        return "reason"
    return "plan"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_reasoner_graph() -> StateGraph:
    """Build and compile the Network Guardian LangGraph reasoning graph."""
    graph = StateGraph(NetworkGuardianState)

    graph.add_node("ingest", ingest_node)
    graph.add_node("reason", reason_node)
    graph.add_node("plan", plan_node)
    graph.add_node("summarize", summarize_node)

    graph.set_entry_point("ingest")
    graph.add_edge("ingest", "reason")

    # Conditional: re-reason if low confidence, otherwise move to plan
    graph.add_conditional_edges(
        "reason",
        _should_re_reason,
        {"reason": "reason", "plan": "plan"},
    )

    graph.add_edge("plan", "summarize")
    graph.add_edge("summarize", END)

    return graph.compile()


# Lazily compiled singleton
_GRAPH: Any = None


def get_reasoner_graph():
    """Return the cached compiled graph (thread-safe via GIL for single-process use)."""
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_reasoner_graph()
    return _GRAPH


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def reason_about_intent(
    intent: str,
    system_state: dict | None = None,
    observations: dict | None = None,
    api_key: str | None = None,
) -> dict:
    """Run the full ingest → reason → plan → summarize pipeline.

    Parameters
    ----------
    intent:
        Free-text user goal (e.g. "scan for malware on 10.0.0.5").
    system_state:
        Live snapshot from ``TriageAgent.SystemState.to_dict()``.
    observations:
        Findings gathered by sub-agents in a prior observation pass.
    api_key:
        DeepSeek API key; falls back to the ``DEEPSEEK_API_KEY`` env var.

    Returns
    -------
    dict with keys:
        intent_class, confidence, action_plan, recommendations,
        deepseek_reasoning, findings, error
    """
    graph = get_reasoner_graph()
    initial_state: NetworkGuardianState = {
        "intent": intent,
        "system_state": system_state or {},
        "observations": observations or {},
        "api_key": api_key or "",
        "messages": [],
        "error": "",
        "iteration": 0,
    }

    result: NetworkGuardianState = await graph.ainvoke(initial_state)

    return {
        "intent_class": result.get("intent_class", "UNKNOWN"),
        "confidence": result.get("confidence", 0.0),
        "action_plan": result.get("action_plan", []),
        "recommendations": result.get("recommendations", []),
        "deepseek_reasoning": result.get("deepseek_reasoning", ""),
        "findings": result.get("findings", []),
        "error": result.get("error", ""),
    }
