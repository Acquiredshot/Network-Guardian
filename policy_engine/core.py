"""Policy Engine core — public API for rule and policy evaluation.


This module exposes the interfaces for loading policies, evaluating
events against them, and producing auditable decisions.
"""

from __future__ import annotations

from typing import Any


class PolicyRule:
    """A single evaluable rule within a policy.

    A rule combines a condition (predicate over event data) with an
    outcome (action + optional metadata) that is applied when the
    condition matches.
    """

    def __init__(self, *, rule_id: str, condition: dict[str, Any], outcome: dict[str, Any]) -> None:
        """Initialise a policy rule.

        Args:
            rule_id: Unique identifier for the rule.
            condition: Dict describing the condition to evaluate.
            outcome: Dict describing the action/decision to apply on match.
        """
        self.rule_id = rule_id
        self.condition = condition
        self.outcome = outcome

    def evaluate(self, *, event: dict[str, Any]) -> bool:
        """Evaluate the rule against an event.

        Args:
            event: Event dict to test.

        Returns:
            ``True`` if the condition matches, ``False`` otherwise.
        """
        pass


class Policy:
    """A named collection of PolicyRules with a decision strategy.

    Policies are evaluated in order; the strategy determines whether
    the first match wins, all matches compose, or the most severe
    outcome wins.
    """

    def __init__(self, *, policy_id: str, rules: list[PolicyRule], strategy: str = "first_match") -> None:
        """Initialise a policy.

        Args:
            policy_id: Unique identifier for the policy.
            policy_rules: Ordered list of rules belonging to this policy.
            strategy: Evaluation strategy — ``first_match``,
                ``deny_overrides``, ``least_privilege``, etc.
        """
        self.policy_id = policy_id
        self.rules = rules
        self.strategy = strategy

    def evaluate(self, *, event: dict[str, Any]) -> dict[str, Any]:
        """Evaluate the policy against an event and return a decision.

        Args:
            event: Event dict to evaluate.

        Returns:
            Decision dict with at minimum ``action``, ``rule_id``, and
            ``reason`` keys.
        """
        pass


class PolicyEngine:
    """The central policy evaluation engine.

    Loads, stores, and evaluates policies against events.  Emits
    AuditEvents for every decision produced.
    """

    def load_policy(self, *, policy: Policy) -> None:
        """Register a policy with the engine.

        Args:
            policy: The Policy to load and make eval-ready.
        """
        pass

    def evaluate(self, *, event: dict[str, Any], policy_id: str | None = None) -> dict[str, Any]:
        """Evaluate an event against one or all loaded policies.

        Args:
            event: Event dict to evaluate.
            policy_id: Optional policy to target; if ``None``, all loaded
                policies are evaluated.

        Returns:
            Decision dict with ``action``, ``policy_id``, ``rule_id``,
            and ``reason``.
        """
        pass

    def list_policies(self) -> list[str]:
        """Return identifiers of all loaded policies.

        Returns:
            List of policy id strings.
        """
        pass
