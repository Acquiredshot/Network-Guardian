# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Access Control Engine — Pakshield pillar.

Evaluates access requests against role/permission/context policies.
Consumes identity risk scores from IdentityRiskEvaluator and the Security
Graph's entity-relationship context to make allow/deny/declare decisions.

Decision flow:
    request ──► policy match ──► context enrichment (risk + graph) ──► verdict
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"  # allow but log + escalate
    CHALLENGE = "challenge"  # require step-up auth


@dataclass
class AccessRequest:
    """A single access-control decision request."""

    subject_id: str
    resource: str
    action: str
    context: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    identity_graph: dict[str, Any] | None = None


@dataclass
class AccessDecision:
    """Outcome of an access-control evaluation."""

    verdict: Verdict
    request: AccessRequest
    policy_id: str = ""
    reason: str = ""
    ttl_seconds: int = 0  # for cached allow decisions


class AccessControlEngine:
    """Phase 1 access-control engine with policy-based evaluation."""

    def __init__(self) -> None:
        self._policies: list[dict[str, Any]] = []
        self._decision_cache: dict[str, AccessDecision] = {}

    # ------------------------------------------------------------------
    # Policy management
    # ------------------------------------------------------------------

    def add_policy(self, policy: dict[str, Any]) -> None:
        """Register a policy rule.

        Policy dict keys:
            id            — unique policy identifier
            resource      — resource pattern (or "*" for any)
            action        — action pattern (or "*" for any)
            role          — required role (or "*" for any)
            min_risk      — maximum allowed risk score (0–100, default 100)
            verdict       — Verdict enum value for matched requests
            reason        — human-readable reason
        """
        self._policies.append(policy)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        """Evaluate a single access request against registered policies."""
        cache_key = f"{request.subject_id}:{request.resource}:{request.action}"
        if cache_key in self._decision_cache:
            cached = self._decision_cache[cache_key]
            if cached.ttl_seconds > 0:
                return cached

        for policy in self._policies:
            if not _policy_matches(policy, request):
                continue

            verdict = Verdict(policy.get("verdict", "deny").upper())
            if verdict == Verdict.ALLOW and request.risk_score > policy.get("min_risk", 100):
                verdict = Verdict.DENY

            decision = AccessDecision(
                verdict=verdict,
                request=request,
                policy_id=policy.get("id", ""),
                reason=policy.get("reason", f"Policy {policy.get('id', '?')} matched"),
            )
            if verdict == Verdict.ALLOW:
                decision.ttl_seconds = 60
                self._decision_cache[cache_key] = decision
            return decision

        # Default-deny
        return AccessDecision(
            verdict=Verdict.DENY,
            request=request,
            reason="No matching policy — default deny",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _policy_matches(policy: dict[str, Any], request: AccessRequest) -> bool:
    """Return True if the policy matches the request."""

    # Resource match
    resource_pat = policy.get("resource", "*")
    if resource_pat != "*" and not _glob_match(resource_pat, request.resource):
        return False

    # Action match
    action_pat = policy.get("action", "*")
    if action_pat != "*" and not _glob_match(action_pat, request.action):
        return False

    # Role match
    required_role = policy.get("role", "*")
    subject_role = str(request.context.get("role", ""))
    if required_role != "*" and required_role != subject_role:
        return False

    return True


def _glob_match(pattern: str, value: str) -> bool:
    """Simple glob match (* and ? wildcards)."""
    import fnmatch

    return fnmatch.fnmatch(value, pattern)
