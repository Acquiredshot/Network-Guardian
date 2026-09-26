# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
AI Security Orchestrator — Detection layer.

Consumes normalized SecurityEvents from the Event Fabric, runs them through
detectors (anomaly scoring, threat correlation, pattern matching), and
produces detection findings that feed Investigation.

Detection pipeline:
    SecurityEvent ──► Detector plugins ──► DetectionFinding ──► Investigation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class DetectionStatus(Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


@dataclass
class DetectionFinding:
    """A single detection result from the orchestrator."""

    finding_id: str
    event_id: str
    detector_name: str
    title: str
    severity: str  # info, low, medium, high, critical
    status: DetectionStatus = DetectionStatus.NEW
    context: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0  # 0..100 confidence
    timestamp: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "event_id": self.event_id,
            "detector": self.detector_name,
            "title": self.title,
            "severity": self.severity,
            "status": self.status.value,
            "score": self.score,
        }


class Detector:
    """Base detector plugin — subclass and register with DetectionEngine."""

    name: str = "base"

    def evaluate(self, event: dict[str, Any]) -> DetectionFinding | None:
        """Return a DetectionFinding if the event warrants attention, else None."""
        raise NotImplementedError


class DetectionEngine:
    """Phase 1 detection engine — runs events through registered detectors."""

    def __init__(self) -> None:
        self._detectors: list[Detector] = []
        self._findings: list[DetectionFinding] = []
        self._counter = 0

    def register(self, detector: Detector) -> None:
        """Register a detector plugin."""
        self._detectors.append(detector)

    def detect(self, event: dict[str, Any]) -> list[DetectionFinding]:
        """Run a single event through all detectors, return findings."""
        findings: list[DetectionFinding] = []
        for detector in self._detectors:
            result = detector.evaluate(event)
            if result is not None:
                result.timestamp = event.get("timestamp", 0.0)
                findings.append(result)
                self._findings.append(result)
        return findings

    def get_findings(self, status: DetectionStatus | None = None) -> list[DetectionFinding]:
        """Return all findings, optionally filtered by status."""
        if status is None:
            return list(self._findings)
        return [f for f in self._findings if f.status == status]

    # ------------------------------------------------------------------
    # Built-in phase 1 detectors
    # ------------------------------------------------------------------

    def add_threat_severity_detector(self) -> None:
        """Detector: escalate finding if event severity is high/critical."""
        self.register(_ThreatSeverityDetector())

    def add_entity_correlation_detector(self) -> None:
        """Detector: flag events touching multiple entities (lateral movement hint)."""
        self.register(_EntityCorrelationDetector())


class _ThreatSeverityDetector(Detector):
    name = "threat_severity"

    def evaluate(self, event: dict[str, Any]) -> DetectionFinding | None:
        sev = str(event.get("severity", "info"))
        if sev in ("high", "critical"):
            return DetectionFinding(
                finding_id=f"finding-{int(event.get('timestamp', 0) * 1000)}",
                event_id=event.get("event_id", ""),
                detector_name=self.name,
                title=f"High-severity {event.get('category', 'event')} from {event.get('source', '?')}",
                severity=sev,
                score=80.0,
                context={"raw_severity": sev},
            )
        return None


class _EntityCorrelationDetector(Detector):
    name = "entity_correlation"

    def evaluate(self, event: dict[str, Any]) -> DetectionFinding | None:
        entities = event.get("entity_ids", [])
        if len(entities) >= 2:
            return DetectionFinding(
                finding_id=f"finding-{int(event.get('timestamp', 0) * 1000)}",
                event_id=event.get("event_id", ""),
                detector_name=self.name,
                title=f"Multi-entity event ({len(entities)} entities) — possible lateral movement",
                severity="medium",
                score=60.0,
                context={"entity_count": len(entities), "entities": entities},
            )
        return None
