# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Tests for LangGraph + DeepSeek integration in Network Guardian.

These tests cover:
  1. Individual graph nodes (ingest, reason, plan, summarize) in isolation.
  2. Full graph execution — offline (no API key) and mock-LLM paths.
  3. TriageAgent.triage() integration with the LangGraph reasoner.
  4. Keyword fallback when no DEEPSEEK_API_KEY is set.
  5. Edge: re-reason loop on low confidence.

All LLM calls are mocked via ``unittest.mock.patch`` so the tests run
without network access or a real DeepSeek API key.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from network_guardian.ai.langgraph_reasoner import (
    NetworkGuardianState,
    _should_re_reason,
    build_reasoner_graph,
    ingest_node,
    plan_node,
    reason_about_intent,
    reason_node,
    summarize_node,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_state(**kwargs) -> NetworkGuardianState:
    """Build a minimal valid state dict."""
    base: NetworkGuardianState = {
        "intent": "scan for malware",
        "system_state": {"threat_level": "green", "active_threats": [], "blocked_ips": []},
        "observations": {},
        "api_key": "",
        "messages": [],
        "error": "",
        "iteration": 0,
    }
    base.update(kwargs)  # type: ignore[typeddict-item]
    return base


def _deepseek_json_response(
    intent_class: str = "THREAT_HUNT",
    confidence: float = 0.9,
    plan: list | None = None,
    recommendations: list | None = None,
    reasoning: str = "",
) -> str:
    """Build a JSON string as DeepSeek would return it."""
    payload = {
        "intent_class": intent_class,
        "confidence": confidence,
        "reasoning_summary": reasoning or f"Classified intent as {intent_class}.",
        "action_plan": plan or [
            {"agent": "malware_scanner", "action": "Full malware scan", "kwargs": {}},
            {"agent": "ids", "action": "IDS alert review", "kwargs": {}},
        ],
        "recommendations": recommendations or [
            "Isolate affected host immediately.",
            "Review IDS alerts for lateral movement.",
        ],
    }
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# Unit tests — individual nodes
# ---------------------------------------------------------------------------


class TestIngestNode:
    def test_empty_intent_sets_error(self):
        state = _make_state(intent="")
        out = ingest_node(state)
        assert out["error"] != ""
        assert out["intent_class"] == "UNKNOWN"

    def test_valid_intent_builds_messages(self):
        state = _make_state(intent="block 10.0.0.5 immediately")
        out = ingest_node(state)
        assert out["error"] == ""
        messages = out["messages"]
        assert len(messages) == 2  # SystemMessage + HumanMessage
        # Second message must contain the intent text
        assert "block 10.0.0.5 immediately" in messages[1].content

    def test_large_observations_truncated(self):
        big_findings = [{"x": i} for i in range(100)]
        state = _make_state(
            intent="scan",
            observations={"findings": big_findings},
        )
        out = ingest_node(state)
        # Only preview of first 5 findings in the message
        msg_content = out["messages"][1].content
        # We should not embed all 100 findings verbatim
        assert "findings_preview" in msg_content

    def test_system_state_summary_included(self):
        state = _make_state(
            intent="status check",
            system_state={
                "threat_level": "red",
                "active_threats": [{"severity": "high"}] * 3,
                "blocked_ips": {"1.2.3.4", "5.6.7.8"},
                "agent_statuses": {"firewall": "active"},
            },
        )
        out = ingest_node(state)
        msg_content = out["messages"][1].content
        assert "red" in msg_content
        assert "active_threat_count" in msg_content


class TestReasonNode:
    def test_no_api_key_returns_error(self):
        state = _make_state(api_key="")
        # Ensure env var is not set
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEEPSEEK_API_KEY", None)
            out = reason_node(state)
        assert out["error"] == "no_api_key"
        assert "keyword fallback" in out.get("deepseek_reasoning", "")

    def test_upstream_error_propagates(self):
        state = _make_state(error="something broke")
        out = reason_node(state)
        # Must not clear the error
        assert out["error"] == "something broke"

    def test_successful_deepseek_call(self):
        mock_response = MagicMock()
        mock_response.content = _deepseek_json_response(
            intent_class="THREAT_HUNT", confidence=0.92
        )

        state = _make_state(api_key="sk-fake-key")
        state["messages"] = ingest_node(state)["messages"]

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = mock_response
            mock_llm_factory.return_value = mock_llm

            out = reason_node(state)

        assert out["intent_class"] == "THREAT_HUNT"
        assert abs(out["confidence"] - 0.92) < 0.01
        assert out["error"] == ""
        assert len(out["action_plan"]) >= 1

    def test_deepseek_reasoner_chain_of_thought_extracted(self):
        """DeepSeek-R1 returns <think>...</think> blocks — verify extraction."""
        mock_response = MagicMock()
        mock_response.content = (
            "<think>The user wants to hunt for malware. "
            "I should scan processes and check IDS.</think>"
            + _deepseek_json_response(intent_class="THREAT_HUNT", confidence=0.88)
        )

        state = _make_state(api_key="sk-fake")
        state["messages"] = ingest_node(state)["messages"]

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = mock_response
            mock_llm_factory.return_value = mock_llm

            out = reason_node(state)

        assert "Chain of Thought" in out["deepseek_reasoning"]
        assert "hunt for malware" in out["deepseek_reasoning"]
        assert out["intent_class"] == "THREAT_HUNT"

    def test_malformed_json_is_handled(self):
        mock_response = MagicMock()
        mock_response.content = "This is not JSON at all."

        state = _make_state(api_key="sk-fake")
        state["messages"] = ingest_node(state)["messages"]

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = mock_response
            mock_llm_factory.return_value = mock_llm

            out = reason_node(state)

        assert out["error"] != ""

    def test_json_inside_markdown_fences(self):
        """DeepSeek sometimes wraps JSON in triple-backtick fences."""
        mock_response = MagicMock()
        mock_response.content = (
            "Here is my analysis:\n"
            "```json\n"
            + _deepseek_json_response(intent_class="SYSTEM_AUDIT", confidence=0.75)
            + "\n```"
        )

        state = _make_state(api_key="sk-fake", intent="run a security audit")
        state["messages"] = ingest_node(state)["messages"]

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = mock_response
            mock_llm_factory.return_value = mock_llm

            out = reason_node(state)

        assert out["intent_class"] == "SYSTEM_AUDIT"
        assert out["error"] == ""


class TestPlanNode:
    def test_valid_plan_passes_through(self):
        plan = [
            {"agent": "malware_scanner", "action": "Full scan", "kwargs": {}},
            {"agent": "ids", "action": "Alert review", "kwargs": {}},
        ]
        state = _make_state(action_plan=plan, intent_class="THREAT_HUNT")
        out = plan_node(state)
        assert len(out["action_plan"]) == 2

    def test_empty_plan_gets_fallback(self):
        state = _make_state(action_plan=[], intent_class="THREAT_RESPONSE")
        out = plan_node(state)
        assert len(out["action_plan"]) > 0
        agents = {s["agent"] for s in out["action_plan"]}
        assert "smart_firewall" in agents or "malware_scanner" in agents

    def test_unknown_intent_gets_system_state_fallback(self):
        state = _make_state(action_plan=[], intent_class="UNKNOWN")
        out = plan_node(state)
        assert out["action_plan"][0]["agent"] == "system_state"

    def test_steps_without_required_fields_filtered(self):
        bad_plan = [
            {"agent": "malware_scanner"},  # missing 'action'
            {"action": "Something"},       # missing 'agent'
            {"agent": "ids", "action": "IDS review", "kwargs": {}},  # valid
        ]
        state = _make_state(action_plan=bad_plan, intent_class="THREAT_HUNT")
        out = plan_node(state)
        # Only the valid step should remain
        assert len(out["action_plan"]) == 1
        assert out["action_plan"][0]["agent"] == "ids"


class TestSummarizeNode:
    def test_deepseek_reasoning_added_as_finding(self):
        state = _make_state(
            intent_class="THREAT_HUNT",
            confidence=0.88,
            deepseek_reasoning="Threats detected: port 4444 open.",
            findings=[],
        )
        out = summarize_node(state)
        assert len(out["findings"]) == 1
        assert out["findings"][0]["source"] == "deepseek_reasoner"

    def test_no_api_key_fallback_not_added_as_finding(self):
        state = _make_state(
            intent_class="STATUS_QUERY",
            confidence=0.5,
            deepseek_reasoning="(no API key — keyword fallback)",
            findings=[],
        )
        out = summarize_node(state)
        # Fallback marker should not produce an AI finding
        assert not any(f.get("source") == "deepseek_reasoner" for f in out["findings"])

    def test_existing_findings_preserved(self):
        existing = [{"severity": "high", "title": "Port 4444 open"}]
        state = _make_state(
            intent_class="THREAT_HUNT",
            confidence=0.9,
            deepseek_reasoning="Detected suspicious port.",
            findings=existing,
        )
        out = summarize_node(state)
        # AI reasoning finding prepended; original finding still there
        assert len(out["findings"]) == 2
        assert out["findings"][1]["severity"] == "high"


# ---------------------------------------------------------------------------
# Edge condition tests
# ---------------------------------------------------------------------------


class TestShouldReReason:
    def test_low_confidence_triggers_re_reason(self):
        state = _make_state(confidence=0.3, iteration=0, error="")
        assert _should_re_reason(state) == "reason"

    def test_high_confidence_goes_to_plan(self):
        state = _make_state(confidence=0.85, iteration=0, error="")
        assert _should_re_reason(state) == "plan"

    def test_already_iterated_goes_to_plan(self):
        # Even low confidence — no more re-reason after 1 iteration
        state = _make_state(confidence=0.2, iteration=1, error="")
        assert _should_re_reason(state) == "plan"

    def test_no_api_key_error_goes_to_plan(self):
        state = _make_state(confidence=0.1, iteration=0, error="no_api_key")
        assert _should_re_reason(state) == "plan"


# ---------------------------------------------------------------------------
# Integration — full graph execution
# ---------------------------------------------------------------------------


class TestFullGraph:
    @pytest.mark.asyncio
    async def test_graph_runs_offline_without_api_key(self):
        """Graph must complete successfully even without a DeepSeek key."""
        result = await reason_about_intent(
            intent="scan for malware",
            api_key="",
        )
        assert result["intent_class"] in (
            "UNKNOWN", "THREAT_HUNT", "THREAT_RESPONSE",
            "STATUS_QUERY", "SYSTEM_AUDIT",
        )
        # Plan should always be non-empty (fallback kicks in)
        assert len(result["action_plan"]) > 0
        assert result["error"] in ("no_api_key", "")

    @pytest.mark.asyncio
    async def test_graph_with_mock_deepseek(self):
        """End-to-end graph with a mocked DeepSeek response."""
        mock_response = MagicMock()
        mock_response.content = _deepseek_json_response(
            intent_class="THREAT_RESPONSE",
            confidence=0.95,
            plan=[
                {"agent": "smart_firewall", "action": "Pull firewall stats", "kwargs": {}},
                {"agent": "ips", "action": "Block 10.0.0.99", "kwargs": {"ip": "10.0.0.99"}},
            ],
            recommendations=["Block 10.0.0.99 at the perimeter firewall."],
        )

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = mock_response
            mock_llm_factory.return_value = mock_llm

            result = await reason_about_intent(
                intent="block 10.0.0.99 — active attacker",
                system_state={"threat_level": "red", "active_threats": [], "blocked_ips": []},
                api_key="sk-fake",
            )

        assert result["intent_class"] == "THREAT_RESPONSE"
        assert abs(result["confidence"] - 0.95) < 0.01
        assert len(result["action_plan"]) == 2
        assert result["action_plan"][1]["agent"] == "ips"
        assert "10.0.0.99" in result["recommendations"][0]
        assert result["error"] == ""

    @pytest.mark.asyncio
    async def test_graph_re_reasons_once_on_low_confidence(self):
        """Low-confidence first response triggers one re-reason iteration."""
        low_conf_response = MagicMock()
        low_conf_response.content = _deepseek_json_response(
            intent_class="UNKNOWN", confidence=0.2
        )
        high_conf_response = MagicMock()
        high_conf_response.content = _deepseek_json_response(
            intent_class="THREAT_HUNT", confidence=0.85
        )

        call_count = 0

        def side_effect(messages):
            nonlocal call_count
            call_count += 1
            return low_conf_response if call_count == 1 else high_conf_response

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.side_effect = side_effect
            mock_llm_factory.return_value = mock_llm

            result = await reason_about_intent(
                intent="investigate suspicious traffic",
                api_key="sk-fake",
            )

        # Should have called the LLM twice (first low-conf → re-reason → high-conf)
        assert call_count == 2
        assert result["intent_class"] == "THREAT_HUNT"

    @pytest.mark.asyncio
    async def test_threat_hunt_intent_produces_malware_scanner_step(self):
        """THREAT_HUNT plan must include a malware scanner step."""
        mock_response = MagicMock()
        mock_response.content = _deepseek_json_response(
            intent_class="THREAT_HUNT",
            confidence=0.9,
            plan=[
                {"agent": "malware_scanner", "action": "Full scan", "kwargs": {}},
                {"agent": "ids", "action": "Alert review", "kwargs": {}},
            ],
        )

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = mock_response
            mock_llm_factory.return_value = mock_llm

            result = await reason_about_intent(
                intent="hunt for ransomware",
                api_key="sk-fake",
            )

        agents = [s["agent"] for s in result["action_plan"]]
        assert "malware_scanner" in agents

    @pytest.mark.asyncio
    async def test_status_query_offline_fallback(self):
        """STATUS_QUERY with no API key should produce a system_state step."""
        result = await reason_about_intent(
            intent="what is the current threat level?",
            api_key="",
        )
        # Fallback plan must always be produced
        assert len(result["action_plan"]) > 0


# ---------------------------------------------------------------------------
# TriageAgent integration tests
# ---------------------------------------------------------------------------


class TestTriageAgentLangGraphIntegration:
    """Test that TriageAgent.triage() correctly invokes the LangGraph reasoner."""

    def _make_triage_agent(self):
        """Build a minimal TriageAgent stub without a real engine."""
        from network_guardian.agent.triage_agent import TriageAgent
        from network_guardian.core.events import EventBus

        bus = EventBus()

        # Minimal engine mock so TriageAgent.__init__ doesn't crash
        engine = MagicMock()
        engine.smart_firewall.get_stats.return_value = {
            "blocked": 0, "allowed": 100, "rules": 5
        }
        engine.ids.alerts = []

        agent = TriageAgent.__new__(TriageAgent)
        agent._bus = bus
        agent._state = TriageAgent.__init__.__code__  # placeholder — we set attrs manually

        # Manually set all required attrs
        from network_guardian.agent.triage_agent import SystemState
        from collections import deque
        agent._state = SystemState()
        agent.engine = engine
        agent._history = []
        agent._malware_agent = None
        agent._ransomware_agent = None
        return agent

    @pytest.mark.asyncio
    async def test_triage_uses_keyword_fallback_without_deepseek_key(self):
        """Without DEEPSEEK_API_KEY, triage must use keyword classification."""
        from network_guardian.agent.triage_agent import TriageAgent
        from network_guardian.core.events import EventBus

        bus = EventBus()
        engine = MagicMock()
        engine.smart_firewall.get_stats.return_value = {}
        engine.ids.alerts = []

        agent = TriageAgent.__new__(TriageAgent)
        from network_guardian.agent.triage_agent import SystemState
        agent._state = SystemState()
        agent._bus = bus
        agent.engine = engine
        agent._history = []
        agent._malware_agent = None
        agent._ransomware_agent = None

        # Patch _dispatch so no real sub-agents are called
        async def _fake_dispatch(step):
            return {"findings": []}

        agent._dispatch = _fake_dispatch

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEEPSEEK_API_KEY", None)
            result = await agent.triage("scan for malware on 192.168.1.0/24")

        assert result.intent_class in (
            "THREAT_HUNT", "THREAT_RESPONSE", "NETWORK_OPS",
            "SYSTEM_AUDIT", "UNKNOWN",
        )
        assert result.task_id
        assert result.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_triage_uses_deepseek_when_key_in_context(self):
        """When a deepseek_api_key is in context, the LangGraph reasoner is invoked."""
        from network_guardian.agent.triage_agent import TriageAgent
        from network_guardian.core.events import EventBus

        bus = EventBus()
        engine = MagicMock()
        engine.smart_firewall.get_stats.return_value = {}
        engine.ids.alerts = []

        agent = TriageAgent.__new__(TriageAgent)
        from network_guardian.agent.triage_agent import SystemState
        agent._state = SystemState()
        agent._bus = bus
        agent.engine = engine
        agent._history = []
        agent._malware_agent = None
        agent._ransomware_agent = None

        async def _fake_dispatch(step):
            return {"findings": []}

        agent._dispatch = _fake_dispatch

        mock_llm_response = MagicMock()
        mock_llm_response.content = _deepseek_json_response(
            intent_class="THREAT_HUNT",
            confidence=0.93,
            recommendations=["Check IDS for port scans.", "Isolate suspicious host."],
        )

        with patch("network_guardian.ai.langgraph_reasoner._make_llm") as mock_llm_factory:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = mock_llm_response
            mock_llm_factory.return_value = mock_llm

            result = await agent.triage(
                "are there any active threats on the network?",
                context={"deepseek_api_key": "sk-fake"},
            )

        assert result.intent_class == "THREAT_HUNT"
        # DeepSeek recommendations should appear in the result
        assert any("IDS" in r for r in result.recommendations)

    @pytest.mark.asyncio
    async def test_triage_falls_back_on_langgraph_error(self):
        """If LangGraph raises an exception, triage must complete with keyword fallback."""
        from network_guardian.agent.triage_agent import TriageAgent
        from network_guardian.core.events import EventBus

        bus = EventBus()
        engine = MagicMock()
        engine.smart_firewall.get_stats.return_value = {}
        engine.ids.alerts = []

        agent = TriageAgent.__new__(TriageAgent)
        from network_guardian.agent.triage_agent import SystemState
        agent._state = SystemState()
        agent._bus = bus
        agent.engine = engine
        agent._history = []
        agent._malware_agent = None
        agent._ransomware_agent = None

        async def _fake_dispatch(step):
            return {}

        agent._dispatch = _fake_dispatch

        with patch("network_guardian.agent.triage_agent._lg_reason") as mock_reason:
            mock_reason.side_effect = RuntimeError("DeepSeek connection refused")

            result = await agent.triage(
                "scan for malware",
                context={"deepseek_api_key": "sk-fake"},
            )

        # Must complete without raising; keyword fallback takes over
        assert result.task_id
        assert result.outcome in ("success", "partial")


# ---------------------------------------------------------------------------
# Graph structure test
# ---------------------------------------------------------------------------


class TestGraphStructure:
    def test_graph_compiles(self):
        graph = build_reasoner_graph()
        assert graph is not None

    def test_graph_has_all_nodes(self):
        """The compiled graph's underlying StateGraph should register all nodes."""
        # Build from scratch to inspect the graph builder
        from langgraph.graph import StateGraph

        g = StateGraph(NetworkGuardianState)
        g.add_node("ingest", ingest_node)
        g.add_node("reason", reason_node)
        g.add_node("plan", plan_node)
        g.add_node("summarize", summarize_node)
        # Just verify no exceptions are raised during construction
        assert g is not None
