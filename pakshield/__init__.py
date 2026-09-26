# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Pakshield — Identity Risk & Access pillar of the Wolf-Pak Platform.

Pakshield sits on top of Network Guardian's detection output and provides:
- Identity risk scoring (anomalous credential use, lateral movement indicators)
- Access control evaluation (role/permission/context-aware decisions)
- Audit and compliance evidence collection (tamper-evident logs, chain of custody)

Pipeline:
    Network Guardian event fabric ──► Pakshield identity risk engine
                                          │
                                          ▼
                              Security Graph (entity relationships)
"""

__version__ = "0.1.0"
__author__ = "Wolf-Pak Innovations LLC"

# Public API surface (phase 1 stubs — fleshed out in subsequent phases)
from pakshield.identity_risk import (
    IdentityRiskEvaluator,
    RiskScore,
    RiskLevel,
)
from pakshield.access_control import (
    AccessControlEngine,
    AccessRequest,
    AccessDecision,
    Verdict,
)

__all__ = [
    "IdentityRiskEvaluator",
    "RiskScore",
    "RiskLevel",
    "AccessControlEngine",
    "AccessRequest",
    "AccessDecision",
    "Verdict",
]
