# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Identity Risk Evaluator — Pakshield pillar.

Scores identity-related risk signals derived from Network Guardian events:
- Anomalous credential use (unfamiliar source, off-hours, unusual volume)
- Lateral movement indicators (new destination after credential use)
- Privilege escalation proximity (repeated auth failures → success)
- Session anomaly (token reuse across disparate locations)

Output: RiskScore (0–100) attached to the identity entity in the Security Graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskScore:
    """A computed identity risk score."""

    identity_id: str
    score: int  # 0–100
    level: RiskLevel
    factors: dict[str, float] = field(default_factory=dict)
    reason: str = ""
    timestamp: float = 0.0

    @classmethod
    def from_event(cls, identity_id: str, event: dict[str, Any]) -> RiskScore:
        """Phase 1 stub — derive a risk score from a single event."""
        score = 0
        factors: dict[str, float] = {}

        # --- Signal: authentication anomaly ---
        auth_anomaly = _auth_anomaly_factor(event)
        if auth_anomaly:
            factors["auth_anomaly"] = auth_anomaly
            score += int(auth_anomaly * 40)

        # --- Signal: source anomaly ---
        source_anomaly = _source_anomaly_factor(event)
        if source_anomaly:
            factors["source_anomaly"] = source_anomaly
            score += int(source_anomaly * 30)

        # --- Signal: privilege proximity ---
        priv_factor = _privilege_proximity_factor(event)
        if priv_factor:
            factors["privilege_proximity"] = priv_factor
            score += int(priv_factor * 30)

        level = RiskLevel.LOW
        if score >= 70:
            level = RiskLevel.CRITICAL
        elif score >= 50:
            level = RiskLevel.HIGH
        elif score >= 25:
            level = RiskLevel.MEDIUM

        return cls(
            identity_id=identity_id,
            score=min(score, 100),
            level=level,
            factors=factors,
            reason=_build_reason(factors),
        )


# ---------------------------------------------------------------------------
# Factor functions (phase 1 — expand in subsequent phases)
# ---------------------------------------------------------------------------

def _auth_anomaly_factor(event: dict[str, Any]) -> float:
    """Return 0..1 based on authentication event anomaly."""
    if event.get("type") != "auth":
        return 0.0
    failures = int(event.get("failure_count", 0))
    if failures >= 5:
        return 1.0
    if failures >= 3:
        return 0.6
    if failures >= 1:
        return 0.3
    return 0.0


def _source_anomaly_factor(event: dict[str, Any]) -> float:
    """Return 0..1 based on source anomaly (new IP, off-hours, etc.)."""
    # Phase 1: simple heuristic — unfamiliar source flagged if not in
    # the known-good set (populated by Security Graph in later phases).
    source = event.get("source_ip", "")
    if not source:
        return 0.0
    # Placeholder: in production this consults a learned baseline.
    return 0.2  # mild default; replace with baseline comparison


def _privilege_proximity_factor(event: dict[str, Any]) -> float:
    """Return 0..1 if the event is close to privilege escalation."""
    role = str(event.get("role", "")).lower()
    if "admin" in role or "root" in role:
        return 0.5
    return 0.0


def _build_reason(factors: dict[str, float]) -> str:
    if not factors:
        return "No significant identity risk signals detected."
    parts = [f"{k}: {v:.0%}" for k, v in sorted(factors.items(), key=lambda x: -x[1])]
    return "Identity risk factors: " + ", ".join(parts)


class IdentityRiskEvaluator:
    """Evaluate identity risk from event streams.

    Consumes authentication, source, and privilege-proximity signals
    to produce a RiskScore for a given identity.
    """

    def evaluate(self, *, identity_id: str, events: list[dict[str, Any]]) -> RiskScore:
        """Compute a RiskScore for an identity from a list of events.

        Args:
            identity_id: The identity to evaluate.
            events: List of event dicts to derive signals from.

        Returns:
            A RiskScore with the computed level and contributing factors.
        """
        # Aggregate all events and derive a single score.
        combined: dict[str, Any] = {}
        for ev in events:
            combined.update(ev)
        return RiskScore.from_event(identity_id, combined)
