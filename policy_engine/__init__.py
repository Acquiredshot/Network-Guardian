# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Policy Engine — rules evaluation for response actions.

Evaluates proposed response actions against policies before they reach
the Action Gateway. See ``milestone_roadmap.md`` for the phased plan.
"""

from __future__ import annotations

from policy_engine.rules import (
    PolicyEngine,
    Policy,
    PolicyVerdict,
    ActionProposal,
)
from policy_engine.evaluation import (
    EvaluationPipeline,
    PlanDecision,
)

__version__ = "0.1.0"
__all__ = [
    "PolicyEngine",
    "Policy",
    "PolicyVerdict",
    "ActionProposal",
    "EvaluationPipeline",
    "PlanDecision",
]
