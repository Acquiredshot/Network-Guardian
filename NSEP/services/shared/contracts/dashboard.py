from datetime import datetime
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel

T = TypeVar("T")


class PageResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class EventRecord(BaseModel):
    event_id: UUID
    source: str
    event_type: str
    occurred_at: datetime
    accepted_at: datetime
    published_at: datetime | None = None
    processed_at: datetime | None = None
    status: Literal["accepted", "published", "processing", "processed", "failed"]
    retry_count: int
    failure_reason: str | None = None
    payload: dict[str, Any]
    metadata: dict[str, Any]
    severity: str | None = None
    incident_id: UUID | None = None
    detections: list[dict[str, str]]


class DetectionRecord(BaseModel):
    detection_id: int
    incident_id: UUID
    event_id: UUID
    rule: str
    severity: str
    detected_at: datetime
    details: dict[str, Any]
    source: str
    event_type: str
    occurred_at: datetime
    incident_status: str
    risk: int


class IncidentRecord(BaseModel):
    incident_id: UUID
    status: Literal["open", "investigating", "resolved"]
    risk: int
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    event_id: UUID
    event_source: str
    event_type: str
    detection_count: int
    highest_severity: str | None = None
    detections: list[dict[str, str]]


class ActivityBucket(BaseModel):
    timestamp: datetime
    count: int


class RuleCount(BaseModel):
    rule: str
    severity: str
    count: int


class DashboardSummary(BaseModel):
    total_events: int
    active_threats: int
    active_incidents: int
    test_event_count: int
    test_active_incidents: int
    test_active_detections: int
    event_activity: list[ActivityBucket]
    active_detections_by_rule: list[RuleCount]


class TimelineEntry(BaseModel):
    timestamp: datetime
    kind: str
    summary: str
    details: dict[str, Any]


class GraphNode(BaseModel):
    id: str
    kind: Literal["event", "incident", "detection"]
    label: str
    details: dict[str, Any]


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class IncidentGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class IntegrationStatus(BaseModel):
    key: str
    name: str
    configured: bool
    reachable: bool | None = None
    detail: str


class IntegrationsStatusResponse(BaseModel):
    integrations: list[IntegrationStatus]