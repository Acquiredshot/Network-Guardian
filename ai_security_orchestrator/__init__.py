# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
AI Security Orchestrator — Detection → Investigation → Response.

Consumes SecurityEvents from the Event Fabric, detects threats, investigates
them with context from the Security Graph, and plans responses that pass
through the Policy Engine and Action Gateway.

Modules:
    detection   — Detector plugins + DetectionEngine
    investigation — InvestigationCase + InvestigationEngine
    response    — ResponsePlanner + ResponsePlan + ResponseAction
"""

from __future__ import annotations

from ai_security_orchestrator.detection import (
    DetectionEngine,
    DetectionFinding,
    Detector,
    DetectionStatus,
)
from ai_security_orchestrator.investigation import (
    InvestigationEngine,
    InvestigationCase,
    CaseStatus,
)
from ai_security_orchestrator.response import (
    ResponsePlanner,
    ResponsePlan,
    ResponseAction,
    ResponseActionType,
)

__version__ = "0.1.0"
__all__ = [
    "DetectionEngine",
    "DetectionFinding",
    "Detector",
    "DetectionStatus",
    "InvestigationEngine",
    "InvestigationCase",
    "CaseStatus",
    "ResponsePlanner",
    "ResponsePlan",
    "ResponseAction",
    "ResponseActionType",
]
