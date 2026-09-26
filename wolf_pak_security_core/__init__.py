# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Wolf-Pak Security Core — the unified security backplane that combines
Network Guardian (detection/response), Pakshield (identity risk + access),
and Mask Network (asset intelligence) into a single integrated platform.

Layers:
    Event Fabric ──► Security Graph ──► Threat Intel
        │
        ▼
    AI Security Orchestrator (Detection → Investigation → Response)
        │
        ▼
    Policy Engine ──► Action Gateway ──► Customer Environment

See ``milestone_roadmap.md`` for the phased implementation plan.
"""

from __future__ import annotations

from wolf_pak_security_core.event_fabric import EventFabric, SecurityEvent, EventCategory
from wolf_pak_security_core.security_graph import SecurityGraph, GraphNode, GraphEdge, NodeType
from ai_security_orchestrator.detection import DetectionEngine, DetectionFinding, Detector
from ai_security_orchestrator.investigation import InvestigationEngine, InvestigationCase
from ai_security_orchestrator.response import ResponsePlanner, ResponsePlan, ResponseAction, ResponseActionType
from policy_engine.rules import PolicyEngine, Policy, PolicyVerdict, ActionProposal
from policy_engine.evaluation import EvaluationPipeline, PlanDecision
from action_gateway import ActionGatewayFacade, ActionGateway, ActionExecutor, ExecutionResult, ExecutionStatus, FirewallApiExecutor

__version__ = "0.1.0"
__all__ = [
    "EventFabric",
    "SecurityEvent",
    "EventCategory",
    "SecurityGraph",
    "GraphNode",
    "GraphEdge",
    "NodeType",
]
