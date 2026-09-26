# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — Autonomous network auditing and system monitoring assistant.

Production-grade IDS/IPS, Smart Firewall, AI threat detection, and remote
access platform. Version 1.0.0.

Subsystems:
    - SmartFirewallAgent: ReAct injection detection & active blocking
    - IntrusionDetectionSystem: signature-based IDS
    - IntrusionPreventionSystem: active IP blocking & rate limiting
    - AIEngine: anomaly detection, forecasting, NLP
    - Dashboard: web-based operations console (port 8080)
    - SaaS: multi-tenant cloud control plane
    - Fleet: distributed probe management
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Wolf-Pak Innovations LLC"
__license__ = "Proprietary"

# Public API — core entry points
from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent

__all__ = [
    "__version__",
    "Config",
    "Engine",
    "SmartFirewallAgent",
]
