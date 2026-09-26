# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Policy Engine — evaluation pipeline.

Evaluates response plans end-to-end through the policy engine,
aggregating per-action verdicts into an overall plan decision.
"""

from __future__ import annotations

from typing import Any

from policy_engine.rules import ActionProposal, PolicyEngine, PolicyVerdict


class PlanDecision:
    """Aggregates per-action policy verdicts into a plan-level decision."""

    def __init__(self) -> None:
        self._results: list[tuple[str, PolicyVerdict, str]] = []  # (action_id, verdict, reason)

    def add(self, action_id: str, verdict: PolicyVerdict, reason: str = "") -> None:
        self._results.append((action_id, verdict, reason))

    @property
    def all_approved(self) -> bool:
        return all(v == PolicyVerdict.APPROVE for _, v, _ in self._results)

    @property
    def any_rejected(self) -> bool:
        return any(v == PolicyVerdict.REJECT for _, v, _ in self._results)

    @property
    def requires_human(self) -> list[tuple[str, str]]:
        """Return list of (action_id, reason) for actions needing human approval."""
        return [(aid, r) for aid, v, r in self._results if v == PolicyVerdict.REQUIRE_HUMAN]

    @property
    def rejected(self) -> list[tuple[str, str]]:
        """Return list of (action_id, reason) for rejected actions."""
        return [(aid, r) for aid, v, r in self._results if v == PolicyVerdict.REJECT]

    @property
    def approved(self) -> list[str]:
        """Return list of action IDs approved by policy."""
        return [aid for aid, v, _ in self._results if v == PolicyVerdict.APPROVE]

    @property
    def overall(self) -> str:
        if self.any_rejected:
            return "blocked"
        if self.requires_human:
            return "pending_human_approval"
        if self.all_approved:
            return "approved"
        return "undecided"


class EvaluationPipeline:
    """End-to-end policy evaluation for a response plan."""

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy_engine = policy_engine
        self._decisions: dict[str, PlanDecision] = {}

    def evaluate_plan(
        self, plan_id: str, actions: list[ActionProposal], context: dict[str, Any] | None = None
    ) -> PlanDecision:
        """Evaluate all actions in a response plan against policies."""
        decision = PlanDecision()
        for action in actions:
            verdict = self._policy_engine.evaluate(action, context)
            reason = self._verdict_reason(verdict)
            decision.add(action.target_id, verdict, reason)
        self._decisions[plan_id] = decision
        return decision

    def get_decision(self, plan_id: str) -> PlanDecision | None:
        return self._decisions.get(plan_id)

    @staticmethod
    def _verdict_reason(verdict: PolicyVerdict) -> str:
        return {
            PolicyVerdict.APPROVE: "Policy-approved",
            PolicyVerdict.REQUIRE_HUMAN: "Requires human approval",
            PolicyVerdict.REJECT: "Policy-rejected",
        }.get(verdict, "Unknown")
