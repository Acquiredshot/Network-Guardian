# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
orchestrator_service.py — wires the AI Security Orchestrator to the
Wolf-Pak Event Fabric.

Subscribes to the EventBus for incoming CrossAppEnvelopes from MASK,
PakShield, and Network Guardian sensors. Runs each event through the
DetectionEngine, feeds confirmed findings to the InvestigationEngine,
and produces ResponsePlans that pass through the Policy Engine and
Action Gateway (stub — Phase C).

Usage:
    python orchestrator_service.py                  # run once, process queued events
    python orchestrator_service.py --daemon         # run continuously, subscribe to bus
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

# Ensure repo root is on path for ai_security_orchestrator imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from network_guardian.core.events import (
    CrossAppEnvelope,
    EventBus,
    EventStorage,
    get_event_bus,
    get_event_storage,
    publish_envelope,
)
from network_guardian.core.security_graph import get_security_graph

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("orchestrator_service")

# Import the real engines from ai_security_orchestrator
from ai_security_orchestrator.detection import (
    DetectionEngine,
    DetectionFinding,
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

# Re-export from the public API module too
from ai_orchestrator.portal import (
    DetectionPipeline,
    InvestigationSession,
    ResponsePlanner as PortalResponsePlanner,
)


# ---------------------------------------------------------------------------
# Detection bridge — EventFabric → DetectionEngine → findings
# ---------------------------------------------------------------------------

class EventFabricDetector:
    """Wraps the DetectionEngine to consume CrossAppEnvelopes from the bus.

    Converts each envelope into a dict the detectors can evaluate, runs
    the built-in detectors, and publishes any resulting findings back to
    the Event Fabric as detection_finding events.
    """

    def __init__(self) -> None:
        self._engine = DetectionEngine()
        self._engine.add_threat_severity_detector()
        self._engine.add_entity_correlation_detector()
        self._findings_published: int = 0

    def ingest(self, envelope: CrossAppEnvelope) -> list[DetectionFinding]:
        """Run a single envelope through the detection engine."""
        event = self._envelope_to_dict(envelope)
        findings = self._engine.detect(event)
        for f in findings:
            logger.info(
                "Detection: [%s] %s (score=%.0f) — evt=%s src=%s",
                f.severity.upper(),
                f.title,
                f.score,
                f.event_id,
                envelope.source,
            )
            self._publish(f, envelope)
        return findings

    def _envelope_to_dict(self, env: CrossAppEnvelope) -> dict[str, Any]:
        """Convert a CrossAppEnvelope into a dict the DetectionEngine accepts."""
        payload = env.payload or {}
        return {
            "event_id": f"evt-{env.timestamp_ms}",
            "timestamp": env.timestamp_ms / 1000.0,
            "event_source": env.source,
            "event_type": env.event_type,
            "severity": env.severity,
            "category": env.category,
            "description": env.description,
            "detector": None,
            "context": {
                "source": env.source,
                "event_type": env.event_type,
                "asset_id": env.asset_id,
                "tenant_id": env.tenant_id,
                "category": env.category,
                "description": env.description,
                **payload,
            },
            "entity_ids": [env.asset_id, env.tenant_id],
        }

    def _publish(
        self, finding: DetectionFinding, envelope: CrossAppEnvelope
    ) -> None:
        try:
            env = CrossAppEnvelope(
                timestamp_ms=int(finding.timestamp * 1000)
                if finding.timestamp
                else int(time.time() * 1000),
                asset_id=envelope.asset_id,
                source="AI_ORCHESTRATOR",
                source_version="0.1.0",
                event_type="detection_finding",
                severity=finding.severity,
                category="detection",
                description=finding.title,
                payload={
                    "native_finding_id": finding.finding_id,
                    "native_event_id": finding.event_id,
                    "detector": finding.detector_name,
                    "score": finding.score,
                    "status": finding.status.value,
                    "context": finding.context,
                    "origin_source": envelope.source,
                    "origin_event_type": envelope.event_type,
                    "origin_asset_id": envelope.asset_id,
                },
                tenant_id=envelope.tenant_id,
            )
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(publish_envelope(env))
            except RuntimeError:
                # No running loop — use asyncio.run for sync context
                try:
                    asyncio.run(publish_envelope(env))
                except RuntimeError:
                    # asyncio.run inside asyncio.run fails — skip
                    pass
            self._published += 1
            logger.info("  Published finding %s → Event Fabric", finding.finding_id)
        except Exception as exc:
            logger.error("  Failed to publish finding %s: %s", finding.finding_id, exc)

    @property
    def findings_count(self) -> int:
        return len(self._engine.get_findings())

    @property
    def published_count(self) -> int:
        return self._findings_published


# ---------------------------------------------------------------------------
# Investigation bridge — DetectionFinding → InvestigationCase
# ---------------------------------------------------------------------------

class InvestigationBridge:
    """Feeds detection findings into the InvestigationEngine."""

    def __init__(self) -> None:
        self._engine = InvestigationEngine()
        self._cases_opened: int = 0

    def investigate(
        self, findings: list[dict[str, Any]]
    ) -> list[InvestigationCase]:
        if not findings:
            return []
        cases = self._engine.investigate(findings)
        for case in cases:
            self._cases_opened += 1
            logger.info(
                "Investigation: case=%s title=%s priority=%s",
                case.case_id,
                case.title,
                case.priority,
            )
        return cases


# ---------------------------------------------------------------------------
# Response bridge — InvestigationCase → ResponsePlan
# ---------------------------------------------------------------------------

class ResponseBridge:
    """Converts investigation results into ResponsePlans."""

    def __init__(self) -> None:
        self._planner = ResponsePlanner()

    def plan(self, findings: list[dict[str, Any]]) -> ResponsePlan | None:
        """Generate a response plan from a list of findings."""
        if not findings:
            return None
        plan = self._planner.plan(findings)
        if plan:
            logger.info(
                "Response plan: case=%s actions=%d scope=%s",
                plan.case_id,
                len(plan.actions),
                plan.status,
            )
        return plan


# ---------------------------------------------------------------------------
# Main orchestrator — end-to-end flow
# ---------------------------------------------------------------------------

class Orchestrator:
    """End-to-end security pipeline: Event Fabric → Detection → Investigation → Response."""

    def __init__(self) -> None:
        self.detector = EventFabricDetector()
        self.investigator = InvestigationBridge()
        self.responder = ResponseBridge()
        self._processed: int = 0
        self._findings: int = 0
        self._cases: int = 0

    def process_envelope(self, envelope: CrossAppEnvelope) -> dict[str, Any]:
        """Run one envelope through the full pipeline."""
        result: dict[str, Any] = {
            "source": envelope.source,
            "event_type": envelope.event_type,
            "asset_id": envelope.asset_id,
            "detections": 0,
            "investigations": 0,
            "responses": 0,
        }

        # Phase 1: Detection
        findings = self.detector.ingest(envelope)
        result["detections"] = len(findings)
        self._findings += len(findings)

        # Phase 2: Investigation (batch findings per source)
        if findings:
            finding_dicts = [f.summary for f in findings]
            cases = self.investigator.investigate(finding_dicts)
            result["investigations"] = len(cases)
            # Phase 3: Response
            plan = self.responder.plan(finding_dicts)
            if plan and plan.actions:
                result["responses"] = len(plan.actions)

        self._processed += 1
        return result

    def process_stored_events(self) -> dict[str, int]:
        """Process all stored events from EventStorage, skipping AI-generated findings."""
        storage = get_event_storage()
        rows = storage.query()
        counts: dict[str, int] = {"processed": 0, "detections": 0, "investigations": 0, "responses": 0}
        skipped = 0
        for row in rows:
            # Skip events generated by this orchestrator to avoid feedback loops
            if row.get("source") == "AI_ORCHESTRATOR":
                skipped += 1
                continue
            try:
                envelope = CrossAppEnvelope.from_dict(row)
                res = self.process_envelope(envelope)
                counts["processed"] += 1
                counts["detections"] += res["detections"]
                counts["investigations"] += res["investigations"]
                counts["responses"] += res["responses"]
            except Exception as exc:
                logger.debug("Skipping row %s: %s", row.get("id", "?"), exc)
        logger.info("Skipped %d AI-generated events (dedup)", skipped)
        return counts

    def subscribe_to_bus(self) -> None:
        """Subscribe to the EventBus for live event processing."""

        def handler(envelope: CrossAppEnvelope) -> None:
            try:
                res = self.process_envelope(envelope)
                logger.info(
                    "Orchestrator: src=%s type=%s det=%d inv=%d resp=%d",
                    res["source"],
                    res["event_type"],
                    res["detections"],
                    res["investigations"],
                    res["responses"],
                )
            except Exception as exc:
                logger.exception("Orchestrator handler error: %s", exc)

        bus = get_event_bus()
        bus.subscribe(handler)
        logger.info("Orchestrator subscribed to EventBus — live processing active")

    @property
    def stats(self) -> dict[str, int]:
        return {
            "processed": self._processed,
            "detections": self._findings,
            "investigations": self._cases,
            "responses": 0,  # responses require case resolution (not implemented yet)
            "findings_published": self.detector.published_count,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="AI Security Orchestrator — Event Fabric → Detection → Investigation → Response"
    )
    ap.add_argument(
        "--once",
        action="store_true",
        help="Process stored events once and exit",
    )
    ap.add_argument(
        "--daemon",
        action="store_true",
        help="Subscribe to EventBus and process events live",
    )
    ap.add_argument(
        "--print-stats",
        action="store_true",
        help="Print orchestrator stats and exit",
    )
    args = ap.parse_args()

    if args.print_stats:
        orch = Orchestrator()
        stats = orch.stats
        print("=== AI Security Orchestrator Stats ===")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        print()
        print("Note: --daemon mode keeps the orchestrator running and subscribed to the EventBus.")
        print("      --once mode processes all stored events from EventStorage.")
        return

    if args.daemon:
        orch = Orchestrator()
        orch.subscribe_to_bus()
        logger.info("Orchestrator daemon running — waiting for events (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Orchestrator stopped")
            print(f"\nStats: {orch.stats}")

    elif args.once:
        orch = Orchestrator()
        logger.info("Processing stored events from EventStorage...")
        counts = orch.process_stored_events()
        logger.info("Done: %s", counts)
        print(f"\nProcessed: {counts}")
        print(f"Stats: {orch.stats}")

    else:
        # Default: process stored events once
        orch = Orchestrator()
        logger.info("Processing stored events from EventStorage...")
        counts = orch.process_stored_events()
        logger.info("Done: %s", counts)
        print(f"\nProcessed: {counts}")
        print(f"Stats: {orch.stats}")


if __name__ == "__main__":
    main()
