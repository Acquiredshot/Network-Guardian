import time
import logging
import socket
from urllib.parse import urlsplit
from uuid import UUID
import psycopg
import redis
from kombu import Connection
from kombu.exceptions import OperationalError
from typing import Literal
from fastapi import APIRouter, HTTPException, Query, Request, status

from shared.contracts.events import BatchRequest, BatchResponse, EventEnvelope, EventStatusResponse, QueuedResponse
from shared.contracts.incidents import IncidentResponse
from shared.contracts.dashboard import (
    DashboardSummary,
    DetectionRecord,
    EventRecord,
    IncidentGraph,
    IncidentRecord,
    IntegrationStatus,
    IntegrationsStatusResponse,
    PageResponse,
    TimelineEntry,
)
from shared.database import (
    get_event_status,
    get_incident as load_incident,
    get_incident_graph,
    get_incident_timeline,
    record_event_accepted,
    update_event_status,
    dashboard_summary as load_dashboard_summary,
    list_detections,
    list_events,
    list_incidents,
)
from shared.schemas import DependencyDiagnostic, DiagnosticsResponse, HealthResponse
from app.config import settings
from app.messaging.rabbitmq import EventPublisher
from app.services.normalization import normalize_event

logger = logging.getLogger("security_event_pipeline.ingestion")

router = APIRouter(prefix="/api")

class DependencyState:
    def __init__(self, publisher: EventPublisher):
        self.publisher = publisher
        self.incidents: dict[UUID, IncidentResponse] = {}


def state(request: Request) -> DependencyState:
    return request.app.state.dependencies

@router.get(
    "/health",
    response_model=HealthResponse,
    response_model_exclude_none=True,
    tags=["Health"],
    summary="Liveness probe",
    description="Returns `ok` when the API process is up. Does not touch any dependencies.",
)
def health() -> HealthResponse:
    return HealthResponse(status="ok")

@router.get(
    "/readiness",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Readiness probe",
    description="Checks the database, broker and cache. Returns **503** if any dependency is unavailable.",
)
def readiness(request: Request) -> HealthResponse:
    services = {
        name: diagnostic.status
        for name, diagnostic in probe_dependencies(
            settings.database_url,
            settings.rabbitmq_url,
            settings.redis_url,
        ).items()
    }
    ready = all(service == "ready" for service in services.values())
    if not ready:
        raise HTTPException(status_code=503, detail={"status": "degraded", "services": services})
    return HealthResponse(status="ok", services=services)


@router.get(
    "/diagnostics",
    response_model=DiagnosticsResponse,
    tags=["Health"],
    summary="Dependency diagnostics",
    description="Reports the status and connection latency of each downstream dependency.",
)
def diagnostics() -> DiagnosticsResponse:
    dependencies = probe_dependencies(
        settings.database_url,
        settings.rabbitmq_url,
        settings.redis_url,
    )
    ready = all(diagnostic.status == "ready" for diagnostic in dependencies.values())
    return DiagnosticsResponse(
        status="ok" if ready else "degraded",
        service="ingestion-api",
        version="0.1.0",
        dependencies=dependencies,
    )


@router.get(
    "/v1/dashboard/summary",
    response_model=DashboardSummary,
    tags=["Dashboard"],
    summary="Dashboard metrics and recent event activity",
)
def dashboard_summary() -> DashboardSummary:
    try:
        return DashboardSummary.model_validate(load_dashboard_summary(settings.database_url))
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Dashboard data unavailable") from exc


def check_tcp_reachable(url: str, timeout: float = 1.5) -> bool:
    """Best-effort TCP connect check. Never sends credentials or protocol payloads."""
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return False
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@router.get(
    "/v1/integrations/status",
    response_model=IntegrationsStatusResponse,
    tags=["Integrations"],
    summary="Live status of downstream integrations",
    description="Reports whether Zammad, Network Guardian, and the MCP server are configured and reachable. Never exposes credentials.",
)
def integrations_status() -> IntegrationsStatusResponse:
    integrations = [
        IntegrationStatus(
            key="zammad",
            name="Zammad ticketing",
            configured=settings.zammad_enabled,
            reachable=check_tcp_reachable(settings.zammad_url) if settings.zammad_enabled else None,
            detail="Automatic ticket creation on new incidents" if settings.zammad_enabled else "Disabled (ZAMMAD_ENABLED=false)",
        ),
        IntegrationStatus(
            key="network_guardian",
            name="Network Guardian Event Fabric",
            configured=settings.network_guardian_enabled,
            reachable=check_tcp_reachable(settings.network_guardian_intake_url) if settings.network_guardian_enabled else None,
            detail="Outbound incident push to Event Fabric" if settings.network_guardian_enabled else "Disabled (NETWORK_GUARDIAN_ENABLED=false)",
        ),
        IntegrationStatus(
            key="mcp_server",
            name="MCP server (Hermes Agent)",
            configured=True,
            reachable=check_tcp_reachable(settings.mcp_server_url),
            detail="Read-only investigation tools over MCP",
        ),
    ]
    return IntegrationsStatusResponse(integrations=integrations)


@router.get(
    "/v1/events",
    response_model=PageResponse[EventRecord],
    tags=["Events"],
    summary="Search and page through persisted events",
)
def search_events(
    q: str | None = Query(default=None, max_length=200),
    source: str | None = Query(default=None, max_length=128),
    event_type: str | None = Query(default=None, max_length=128),
    event_status: Literal["accepted", "published", "processing", "processed", "failed"] | None = Query(default=None, alias="status"),
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    sort_by: Literal["occurred_at", "accepted_at", "source", "event_type", "status"] = "occurred_at",
    sort_order: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PageResponse[EventRecord]:
    try:
        data = list_events(
            settings.database_url,
            limit=limit,
            offset=offset,
            query=q,
            source=source,
            event_type=event_type,
            status=event_status,
            severity=severity,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return PageResponse[EventRecord].model_validate(data)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Event search unavailable") from exc


@router.get(
    "/v1/detections",
    response_model=PageResponse[DetectionRecord],
    tags=["Threats"],
    summary="Search and page through persisted detections",
)
def search_detections(
    q: str | None = Query(default=None, max_length=200),
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    rule: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PageResponse[DetectionRecord]:
    try:
        data = list_detections(
            settings.database_url,
            limit=limit,
            offset=offset,
            query=q,
            severity=severity,
            rule=rule,
        )
        return PageResponse[DetectionRecord].model_validate(data)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Detection search unavailable") from exc


@router.get(
    "/v1/incidents",
    response_model=PageResponse[IncidentRecord],
    tags=["Incidents"],
    summary="Search and page through incidents",
)
def search_incidents(
    q: str | None = Query(default=None, max_length=200),
    incident_status: Literal["open", "investigating", "resolved"] | None = Query(default=None, alias="status"),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PageResponse[IncidentRecord]:
    try:
        data = list_incidents(
            settings.database_url,
            limit=limit,
            offset=offset,
            query=q,
            status=incident_status,
        )
        return PageResponse[IncidentRecord].model_validate(data)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Incident search unavailable") from exc


@router.get(
    "/v1/incidents/{incident_id}/timeline",
    response_model=list[TimelineEntry],
    tags=["Incidents"],
    summary="Get persisted event, detection, and incident lifecycle history",
)
def incident_timeline(incident_id: UUID) -> list[TimelineEntry]:
    try:
        if load_incident(settings.database_url, incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return [TimelineEntry.model_validate(row) for row in get_incident_timeline(settings.database_url, incident_id)]
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Incident timeline unavailable") from exc


@router.get(
    "/v1/incidents/{incident_id}/graph",
    response_model=IncidentGraph,
    tags=["Incidents"],
    summary="Get event, incident, and detection relationships",
)
def incident_graph(incident_id: UUID) -> IncidentGraph:
    try:
        graph = get_incident_graph(settings.database_url, incident_id)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Incident graph unavailable") from exc
    if graph is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentGraph.model_validate(graph)

@router.post(
    "/v1/events",
    response_model=QueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Events"],
    summary="Publish a security event",
    description="Normalizes the event, persists it and queues it for processing.",
)
def publish_event(event: EventEnvelope, request: Request) -> QueuedResponse:
    normalized = normalize_event(event)
    try:
        record_event_accepted(settings.database_url, normalized.model_dump(mode="json"))
    except psycopg.Error as exc:
        logger.warning(
            "event_persistence_failed",
            extra={"event_id": str(normalized.event_id), "request_id": getattr(request.state, "request_id", None)},
            exc_info=True,
        )
        raise HTTPException(status_code=503, detail="Event store unavailable") from exc
    try:
        state(request).publisher.publish(normalized)
        logger.info(
            "event_published",
            extra={
                "event_id": str(normalized.event_id),
                "event_type": normalized.event_type,
                "request_id": getattr(request.state, "request_id", None),
            },
        )
    except Exception as exc:
        logger.warning(
            "event_publish_failed",
            extra={"event_id": str(normalized.event_id), "request_id": getattr(request.state, "request_id", None)},
            exc_info=True,
        )
        raise HTTPException(status_code=503, detail="Event broker unavailable") from exc
    try:
        update_event_status(settings.database_url, normalized.event_id, "published")
    except psycopg.Error:
        logger.exception("event_status_update_failed", extra={"event_id": str(normalized.event_id)})
    return QueuedResponse(event_id=normalized.event_id, accepted_at=normalized.accepted_at)

@router.post(
    "/v1/events/batch",
    response_model=BatchResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Events"],
    summary="Publish a batch of events",
    description="Accepts several events in one request and returns the IDs of the queued events.",
)
def publish_batch(batch: BatchRequest, request: Request) -> BatchResponse:
    accepted: list[UUID] = []
    try:
        for event in batch.events:
            normalized = normalize_event(event)
            try:
                record_event_accepted(settings.database_url, normalized.model_dump(mode="json"))
            except psycopg.Error as exc:
                raise HTTPException(status_code=503, detail="Event store unavailable") from exc
            state(request).publisher.publish(normalized)
            try:
                update_event_status(settings.database_url, normalized.event_id, "published")
            except psycopg.Error:
                logger.exception("event_status_update_failed", extra={"event_id": str(normalized.event_id)})
            accepted.append(normalized.event_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Event broker unavailable") from exc
    return BatchResponse(accepted=len(accepted), rejected=len(batch.events) - len(accepted), event_ids=accepted)


@router.get(
    "/v1/events/{event_id}",
    response_model=EventStatusResponse,
    tags=["Events"],
    summary="Get event status",
    description="Looks up an event's processing status by ID.",
)
def get_event(event_id: UUID) -> EventStatusResponse:
    try:
        event = get_event_status(settings.database_url, event_id)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Event store unavailable") from exc
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventStatusResponse.model_validate(event)

@router.get(
    "/v1/incidents/{incident_id}",
    response_model=IncidentResponse,
    tags=["Incidents"],
    summary="Get an incident",
    description="Returns a correlated incident, created by the processing workers, by ID.",
)
def get_incident(incident_id: UUID, request: Request) -> IncidentResponse:
    try:
        incident = load_incident(settings.database_url, incident_id)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Incident store unavailable") from exc
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentResponse.model_validate(incident)


def probe_dependencies(
    database_url: str,
    rabbitmq_url: str,
    redis_url: str,
) -> dict[str, DependencyDiagnostic]:
    services = {
        "database": DependencyDiagnostic(status="unavailable"),
        "broker": DependencyDiagnostic(status="unavailable"),
        "cache": DependencyDiagnostic(status="unavailable"),
    }
    try:
        started = time.perf_counter()
        with psycopg.connect(database_url, connect_timeout=2) as connection:
            connection.execute("SELECT 1")
        services["database"] = DependencyDiagnostic(
            status="ready",
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
    except psycopg.Error:
        pass

    try:
        started = time.perf_counter()
        with Connection(rabbitmq_url, connect_timeout=2) as connection:
            connection.ensure_connection(max_retries=0)
        services["broker"] = DependencyDiagnostic(
            status="ready",
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
    except OperationalError:
        pass

    cache = redis.Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
    try:
        started = time.perf_counter()
        cache.ping()
        services["cache"] = DependencyDiagnostic(
            status="ready",
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
    except redis.RedisError:
        pass
    finally:
        cache.close()
    return services


def check_dependencies(database_url: str, rabbitmq_url: str, redis_url: str) -> dict[str, str]:
    return {
        name: diagnostic.status
        for name, diagnostic in probe_dependencies(database_url, rabbitmq_url, redis_url).items()
    }
