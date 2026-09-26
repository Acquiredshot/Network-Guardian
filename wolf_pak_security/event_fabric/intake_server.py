# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
"""
Event Fabric intake server — aiohttp HTTP endpoint that accepts the common
event envelope (see WOLF-PAK_CORRELATION_SPEC.md §2.1) from external apps
(MASK, PakShield, Network Guardian sensors) and routes events through the
EventBus + EventStorage + SecurityGraph.

Run:
    python -m wolf_pak_security.event_fabric.intake_server  # port 8090
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from aiohttp import web

from network_guardian.config import Config

from wolf_pak_security.events import DetectionEvent, DetectionBatch, IntelEvent, AuditEvent
from wolf_pak_security.event_fabric.core import EventBus, EventEnvelope, EventStorage
from wolf_pak_security.security_graph.core import GraphEntity, GraphRelationship, SecurityGraph

logger = logging.getLogger("wolf_pak_security.event_fabric.intake")

# ---------------------------------------------------------------------------
# Global fabric components (singleton for the intake server process)
# ---------------------------------------------------------------------------

bus = EventBus()
storage = EventStorage()
graph = SecurityGraph()

# Wire graph as a subscriber to the "detection" family so it ingests
# every detection event that flows through the bus.
def _graph_ingest(envelope: EventEnvelope) -> None:
    payload = envelope.payload
    if isinstance(payload, DetectionEvent):
        event_dict = {
            "event_id": payload.event_id,
            "source": envelope.source,
            "timestamp_ms": int(payload.timestamp.timestamp() * 1000),
            "severity": payload.severity,
            "category": payload.category,
            "description": payload.description,
            "asset_id": payload.context.get("asset_id", ""),
            "payload": payload.context,
        }
        graph.ingest_detection(event_dict)

bus.subscribe(family="detection", callback=_graph_ingest)


def _serialize_event(obj: Any) -> Any:
    """JSON-serialisable representation of an event dataclass."""
    if hasattr(obj, "__dataclass_fields__"):
        return {f.name: getattr(obj, f.name) for f in obj.__dataclass_fields__.values()}
    return obj


# ---------------------------------------------------------------------------
# Intake endpoint
# ---------------------------------------------------------------------------

INTAKE_ROUTE = "/api/event-fabric/intake"
HEALTH_ROUTE = "/api/event-fabric/health"


class IntakeHandler:
    """Handles POST /api/event-fabric/intake — accepts the common envelope."""

    async def post_intake(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"status": "error", "message": "Request body must be JSON"},
                status=400,
            )

        if not isinstance(body, dict):
            return web.json_response(
                {"status": "error", "message": "Envelope must be a JSON object"},
                status=400,
            )

        # Validate required envelope fields
        timestamp_ms = body.get("timestamp_ms")
        asset_id = body.get("asset_id", "")
        source = body.get("source", "")
        event_type = body.get("event_type", "")
        severity = body.get("severity", "info")
        category = body.get("category", "")
        description = body.get("description", "")
        payload = body.get("payload", {})

        if not isinstance(timestamp_ms, (int, float)):
            return web.json_response(
                {"status": "error", "message": "'timestamp_ms' must be an integer"},
                status=400,
            )
        if not source:
            return web.json_response(
                {"status": "error", "message": "'source' is required"},
                status=400,
            )
        if not event_type:
            return web.json_response(
                {"status": "error", "message": "'event_type' is required"},
                status=400,
            )

        event_id = body.get("event_id") or str(uuid.uuid4())
        ts = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc)

        # Map source string to event family for routing
        family_map = {
            "NETWORK_GUARDIAN": "detection",
            "MASK": "detection",
            "PAKSHIELD": "detection",
        }
        family = family_map.get(source.upper(), "detection")

        # Build the appropriate event dataclass
        if family == "detection":
            event = DetectionEvent(
                event_id=event_id,
                source=source,
                timestamp=ts,
                severity=severity,
                category=category,
                description=description,
                context={
                    "asset_id": asset_id,
                    "event_type": event_type,
                    "payload": payload,
                    "source_version": body.get("source_version", ""),
                },
            )
        elif family == "audit":
            event = AuditEvent(
                audit_id=event_id,
                timestamp=ts,
                actor=body.get("actor", source),
                action=event_type,
                target=asset_id,
                decision_reason=description,
                outcome=body.get("outcome", "success"),
                context={"payload": payload, "source_version": body.get("source_version", "")},
            )
        else:
            event = IntelEvent(
                intel_id=event_id,
                timestamp=ts,
                intel_type=event_type,
                source=source,
                indicator=body.get("indicator", ""),
                indicator_type=body.get("indicator_type", ""),
                confidence=float(body.get("confidence", 0.0)),
                description=description,
                metadata={"payload": payload, "source_version": body.get("source_version", "")},
            )

        envelope = EventEnvelope(family=family, payload=event, source=source)

        # Persist + publish
        storage.store(envelope=envelope)
        bus.publish(envelope=envelope)

        logger.info(
            "Ingested %s event: id=%s source=%s type=%s asset=%s severity=%s",
            family,
            event_id,
            source,
            event_type,
            asset_id,
            severity,
        )

        return web.json_response(
            {
                "status": "accepted",
                "event_id": event_id,
                "family": family,
                "ingested_at": datetime.now(tz=timezone.utc).isoformat(),
            },
            status=202,
        )

    async def get_health(self, request: web.Request) -> web.Response:
        return web.json_response(
            {
                "status": "ok",
                "service": "wolf-pak-event-fabric-intake",
                "version": "0.1.0",
            }
        )


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> web.Application:
    app = web.Application()
    handler = IntakeHandler()
    app.router.add_post(INTAKE_ROUTE, handler.post_intake)
    app.router.add_get(HEALTH_ROUTE, handler.get_health)
    return app


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Wolf-Pak Event Fabric Intake Server")
    parser.add_argument("--port", type=int, default=8090, help="Port to listen on (default: 8090)")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = create_app()
    logger.info("Starting Event Fabric intake server on port %d", args.port)
    logger.info("Intake endpoint: http://127.0.0.1:%d%s", args.port, INTAKE_ROUTE)
    logger.info("Health endpoint: http://127.0.0.1:%d%s", args.port, HEALTH_ROUTE)

    web.run_app(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
