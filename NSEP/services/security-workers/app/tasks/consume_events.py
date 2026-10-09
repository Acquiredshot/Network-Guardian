import logging
from typing import Any

from shared.database import persist_event_result, update_event_status

from app.celery_app import celery
from app.detection.rules import detect
from app.enrichment.pipeline import enrich
from app.incidents.lifecycle import create_incident
from app.integrations.network_guardian import NetworkGuardianClient
from app.integrations.zammad import ZammadClient, severity_to_priority
from app.risk.scoring import score
from app.settings import settings

logger = logging.getLogger("security_event_pipeline.worker")

zammad = ZammadClient()
network_guardian = NetworkGuardianClient()


@celery.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def process_event(self: Any, event: dict[str, Any]) -> dict[str, Any]:
    logger.info(
        "event_processing_started",
        extra={
            "event_id": str(event.get("event_id")),
            "event_type": event.get("event_type"),
        },
    )

    update_event_status(
        settings.database_url,
        event["event_id"],
        "processing",
        retry_count=self.request.retries,
    )

    try:
        enriched = enrich(event)
        detections = detect(enriched)
        risk = score(detections)

        incident = (
            create_incident(enriched, detections, risk)
            if detections
            else None
        )

        # Persist the NSEP event and incident first.
        persist_event_result(
            settings.database_url,
            enriched,
            incident,
        )

        # Zammad is downstream of the NSEP incident system.
        # A Zammad failure must not destroy the security incident.
        zammad_ticket = None
        network_guardian_result = None

        if incident:
            highest_severity = max(
                (
                    detection.get("severity", "low")
                    for detection in detections
                ),
                key=lambda severity: {
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                    "critical": 4,
                }.get(severity, 0),
            )

            detection_summary = "\n".join(
                f"- {detection.get('rule')} | {detection.get('severity')}"
                for detection in detections
            )

            article_body = f"""
NSEP Security Incident

Incident ID: {incident["incident_id"]}
Event ID: {enriched.get("event_id")}
Risk Score: {risk}
Highest Severity: {highest_severity}

Source: {enriched.get("source")}
Event Type: {enriched.get("event_type")}
Occurred At: {enriched.get("occurred_at")}

Detections:
{detection_summary}

This ticket was automatically created by the Network Security Event Pipeline.
""".strip()

            zammad_ticket = zammad.create_ticket(
                title=f"[NSEP] {highest_severity.upper()} Security Incident",
                article_body=article_body,
                priority_id=severity_to_priority(highest_severity),
            )

            # Network Guardian is downstream of the NSEP incident system, same as Zammad.
            # A push failure must not destroy the security incident.
            network_guardian_result = network_guardian.push_incident(
                incident_id=str(incident["incident_id"]),
                event_id=str(enriched.get("event_id")),
                source=enriched.get("source", ""),
                event_type=enriched.get("event_type", ""),
                severity=highest_severity,
                risk=risk,
                detections=detections,
            )

        logger.info(
            "event_processing_completed",
            extra={
                "event_id": str(enriched.get("event_id")),
                "incident_id": (
                    str(incident["incident_id"])
                    if incident
                    else None
                ),
                "detection_count": len(detections),
                "risk": risk,
                "zammad_ticket_id": (
                    zammad_ticket.get("id")
                    if zammad_ticket
                    else None
                ),
                "zammad_ticket_number": (
                    zammad_ticket.get("number")
                    if zammad_ticket
                    else None
                ),
                "network_guardian_row_id": (
                    network_guardian_result.get("row_id")
                    if network_guardian_result
                    else None
                ),
                "network_guardian_graph_nodes": (
                    network_guardian_result.get("graph_nodes")
                    if network_guardian_result
                    else None
                ),
            },
        )

        return {
            "event": enriched,
            "incident": incident,
            "zammad_ticket": (
                {
                    "id": zammad_ticket.get("id"),
                    "number": zammad_ticket.get("number"),
                }
                if zammad_ticket
                else None
            ),
            "network_guardian": (
                {
                    "row_id": network_guardian_result.get("row_id"),
                    "graph_nodes": network_guardian_result.get("graph_nodes"),
                }
                if network_guardian_result
                else None
            ),
        }

    except Exception as exc:
        update_event_status(
            settings.database_url,
            event["event_id"],
            "failed",
            failure_reason=type(exc).__name__,
            retry_count=self.request.retries + 1,
        )

        logger.exception(
            "event_processing_failed",
            extra={
                "event_id": str(event.get("event_id")),
            },
        )

        raise
