# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
AI Security Orchestrator — Response layer.

Consumes InvestigationCases from the Investigation layer and,
once a case is confirmed, translates it into actionable response
commands that pass through the Policy Engine and Action Gateway.

Response pipeline:
    InvestigationCase (confirmed) ──► ResponsePlan ──► Policy Engine ──► Action Gateway
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ResponseActionType(Enum):
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    TERMINATE_PROCESS = "terminate_process"
    REVOKE_TOKEN = "revoke_token"
    FORCE_PASSWORD_RESET = "force_password_reset"
    QUARANTINE_FILE = "quarantine_file"
    ALERT_ONLY = "alert_only"


@dataclass
class ResponseAction:
    """A single action proposed by the response planner."""

    action_type: ResponseActionType
    target_id: str  # asset_id, identity_id, ip, etc.
    parameters: dict[str, Any] = field(default_factory=dict)
    justification: str = ""
    priority: str = "medium"  # low, medium, high, critical


@dataclass
class ResponsePlan:
    """A planned response derived from a confirmed investigation case."""

    case_id: str
    title: str
    status: str = "pending_approval"  # pending_approval, approved, executed, rejected
    actions: list[ResponseAction] = field(default_factory=list)
    rationale: str = ""
    created_at: float = 0.0
    executed_at: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status,
            "action_count": len(self.actions),
            "highest_priority": self._highest_priority(),
        }

    def _highest_priority(self) -> str:
        priority_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        best = "low"
        best_score = 1
        for action in self.actions:
            score = priority_order.get(action.priority, 0)
            if score > best_score:
                best_score = score
                best = action.priority
        return best


class ResponsePlanner:
    """Phase 1 response planner — generates response actions from findings."""

    def __init__(self) -> None:
        self._action_rules: list[dict[str, Any]] = []

    def register_rule(self, rule: dict[str, Any]) -> None:
        """Register a response rule.

        Rule dict keys:
            finding_severity  — minimum severity to trigger (info/low/medium/high/critical)
            finding_type      — detector name or finding type to match
            action_type       — ResponseActionType to propose
            target_field      — which finding context key holds the target ID
            justification     — human-readable reason
            priority          — action priority (default "medium")
            parameters        — extra parameters to attach to the action
        """
        self._action_rules.append(rule)

    def plan(self, findings: list[dict[str, Any]]) -> ResponsePlan:
        """Generate a response plan from a list of findings.

        Phase 1: rule-based action generation.
        Phase 2+: ML-assisted plan prioritization, auto-approval thresholds.
        """
        now = 0.0
        actions: list[ResponseAction] = []

        for finding in findings:
            sev = finding.get("severity", "info")
            ftype = finding.get("detector", finding.get("type", ""))
            context = finding.get("context", {})

            for rule in self._action_rules:
                if not _rule_matches(rule, sev, ftype):
                    continue

                target_id = context.get(rule.get("target_field", ""), finding.get("event_id", ""))
                if not target_id:
                    continue

                action = ResponseAction(
                    action_type=ResponseActionType(rule["action_type"]),
                    target_id=target_id,
                    parameters=rule.get("parameters", {}),
                    justification=rule.get("justification", f"Triggered by {ftype} finding"),
                    priority=rule.get("priority", "medium"),
                )
                actions.append(action)

        return ResponsePlan(
            case_id=findings[0].get("finding_id", "unknown") if findings else "unknown",
            title=f"Response plan for {len(findings)} finding(s)",
            status="pending_approval",
            actions=actions,
            rationale="Auto-generated response plan from rule-based planner",
            created_at=now,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _rule_matches(rule: dict[str, Any], finding_sev: str, finding_type: str) -> bool:
    """Return True if a rule matches a finding."""
    min_sev = rule.get("finding_severity", "info")
    if SEVERITY_ORDER.get(finding_sev, 0) < SEVERITY_ORDER.get(min_sev, 0):
        return False

    required_type = rule.get("finding_type", "")
    if required_type and required_type != finding_type:
        return False

    return True
