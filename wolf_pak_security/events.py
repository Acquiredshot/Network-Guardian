"""Shared event schema — dataclasses flowing through the Event Fabric.


All Wolf-Pak modules emit and consume events defined here.  The three
families are:

* **Detection** events — surfaced by sensors and the AI Orchestrator
  when something notable is observed.
* **Intel** events — threat intelligence, indicators, and enrichment
  data published by the Threat Intel layer.
* **Audit** events — lifecycle and decision records produced by the
  Policy Engine and Action Gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── helpers ────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


# ── Detection events ───────────────────────────────────────

@dataclass
class DetectionEvent:
    """A single security-relevant observation emitted by a sensor.

    Detection events flow from raw sensors and the AI Orchestrator into
    the Event Fabric, where the Security Graph ingests them and the
    Policy Engine evaluates them.
    """

    event_id: str
    """Unique identifier for this event."""

    source: str = ""
    """Name of the sensor / module that produced the detection."""

    timestamp: datetime = field(default_factory=_now)
    """When the detection was generated (UTC)."""

    severity: str = "info"
    """One of ``info``, ``low``, ``medium``, ``high``, ``critical``."""

    category: str = ""
    """High-level taxonomy, e.g. ``process``, ``network``, ``auth``, ``file``."""

    description: str = ""
    """Human-readable summary of what was observed."""

    context: dict[str, Any] = field(default_factory=dict)
    """Extra structured data attached to the detection."""


@dataclass
class DetectionBatch:
    """A bundle of DetectionEvents produced together (e.g. from a bulk scan)."""

    source: str
    detections: list[DetectionEvent] = field(default_factory=list)
    batch_id: str = ""


# ── Intel events ───────────────────────────────────────────

@dataclass
class IntelEvent:
    """A threat-intelligence record published by the Threat Intel layer.

    Intel events carry indicators, enrichments, and reputation data
    that other modules subscribe to for decision-making.
    """

    intel_id: str
    """Stable identifier for this intelligence item."""

    timestamp: datetime = field(default_factory=_now)
    """When the intel was generated or last refreshed (UTC)."""

    intel_type: str = ""
    """Category: ``indicator``, ``report``, ``campaign``, ``tactic``."""

    source: str = ""
    """Origin of the intelligence (feed name, vendor, internal)."""

    indicator: str = ""
    """The observable value (hash, domain, IP, signature) when applicable."""

    indicator_type: str = ""
    """Type of the indicator when present: ``sha256``, ``domain``, ``ip``."""

    confidence: float = 0.0
    """Confidence score 0.0 – 1.0 for the intelligence item."""

    description: str = ""
    """Narrative description or summary of the intelligence."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Extra structured fields (TTPs, references, labels, etc.)."""


# ── Audit events ───────────────────────────────────────────

@dataclass
class AuditEvent:
    """A lifecycle or decision record produced by Policy Engine and Action Gateway.

    Audit events are append-only and feed compliance, forensics, and
    replay tooling.
    """

    audit_id: str
    """Unique identifier for this audit record."""

    timestamp: datetime = field(default_factory=_now)
    """When the audited action occurred (UTC)."""

    actor: str = ""
    """Principal or system component that initiated the action."""

    action: str = ""
    """What happened: ``allow``, ``deny``, `` escalate``, ``quarantine``, etc."""

    target: str = ""
    """The object the action was performed on (policy id, host, file, etc.)."""

    decision_reason: str = ""
    """Why the decision was made (rule name, policy snippet, rationale)."""

    outcome: str = ""
    """Result of the action: ``success``, ``failure``, ``pending``."""

    context: dict[str, Any] = field(default_factory=dict)
    """Supplementary structured data about the audited event."""
