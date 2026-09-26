# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Policy Engine — rules and evaluation layer.

Evaluates proposed response actions against policies before they reach the
Action Gateway. Policies encode:
- Approval thresholds (auto-approve low-risk, require human for high-risk)
- Scope constraints (which environments/tenants an action applies to)
- Safety constraints (prevent self-inflicted outages)
- Audit requirements (what must be logged before action execution)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyVerdict(Enum):
    APPROVE = "approve"
    REQUIRE_HUMAN = "require_human"
    REJECT = "reject"


@dataclass
class Policy:
    """A single policy rule for the policy engine."""

    id: str
    name: str
    description: str = ""
    scope: dict[str, Any] = field(default_factory=dict)  # environment, tenant, asset_tags
    min_action_severity: str = "low"  # info, low, medium, high, critical
    requires_human_above: str = "high"  # action priority that requires human approval
    allowed_action_types: set[str] | None = None  # if set, only these types are allowed
    unsafe_action_types: set[str] | None = None  # if set, these types are blocked
    audit_required: bool = True
    auto_approve: bool = False

    def evaluate(self, action: "ActionProposal", context: dict[str, Any]) -> PolicyVerdict:
        """Evaluate whether an action is allowed under this policy."""
        # Scope check
        if not _scope_matches(self.scope, context):
            return PolicyVerdict.REJECT

        # Action type allowlist
        if self.allowed_action_types is not None:
            if action.action_type not in self.allowed_action_types:
                return PolicyVerdict.REJECT

        # Unsafe action blocklist
        if self.unsafe_action_types is not None:
            if action.action_type in self.unsafe_action_types:
                return PolicyVerdict.REJECT

        # Human approval threshold
        action_priority = action.priority
        if action_priority == self.requires_human_above or _higher_priority(action_priority, self.requires_human_above):
            return PolicyVerdict.REQUIRE_HUMAN

        if self.auto_approve:
            return PolicyVerdict.APPROVE

        return PolicyVerdict.REQUIRE_HUMAN


@dataclass
class ActionProposal:
    """A proposed action awaiting policy evaluation."""

    action_type: str
    target_id: str
    parameters: dict[str, Any] = field(default_factory=dict)
    priority: str = "medium"
    source: str = "response_planner"
    justification: str = ""
    proposed_at: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target_id": self.target_id,
            "priority": self.priority,
            "source": self.source,
        }


class PolicyEngine:
    """Phase 1 policy engine — evaluates action proposals against policies."""

    def __init__(self) -> None:
        self._policies: list[Policy] = []
        self._evaluation_log: list[dict[str, Any]] = []

    def add_policy(self, policy: Policy) -> None:
        self._policies.append(policy)

    def evaluate(self, proposal: ActionProposal, context: dict[str, Any] | None = None) -> PolicyVerdict:
        """Evaluate a single action proposal against all registered policies.

        Returns the most restrictive verdict across all matching policies.
        """
        if context is None:
            context = {}

        overall: PolicyVerdict | None = None
        for policy in self._policies:
            verdict = policy.evaluate(proposal, context)
            if overall is None:
                overall = verdict
            elif verdict == PolicyVerdict.REJECT:
                overall = PolicyVerdict.REJECT
            elif verdict == PolicyVerdict.REQUIRE_HUMAN and overall == PolicyVerdict.APPROVE:
                overall = PolicyVerdict.REQUIRE_HUMAN

        self._evaluation_log.append({
            "proposal_summary": proposal.summary,
            "context_keys": sorted(context.keys()),
            "verdict": overall.value if overall else "no_policy",
        })

        return overall if overall is not None else PolicyVerdict.REQUIRE_HUMAN

    def get_audit_log(self) -> list[dict[str, Any]]:
        return list(self._evaluation_log)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PRIORITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _higher_priority(a: str, b: str) -> bool:
    return PRIORITY_ORDER.get(a, 0) > PRIORITY_ORDER.get(b, 0)


def _scope_matches(scope: dict[str, Any], context: dict[str, Any]) -> bool:
    """Return True if context satisfies the policy scope."""
    for key, expected in scope.items():
        actual = context.get(key)
        if actual is None:
            return False
        if isinstance(expected, set):
            if actual not in expected:
                return False
        elif str(actual) != str(expected):
            return False
    return True
