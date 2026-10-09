from datetime import datetime
from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel, Field

class EventEnvelope(BaseModel):
    source: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    occurred_at: datetime
    payload: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)

class NormalizedEvent(EventEnvelope):
    event_id: UUID
    accepted_at: datetime

class BatchRequest(BaseModel):
    events: list[EventEnvelope] = Field(min_length=1, max_length=100)

class BatchResponse(BaseModel):
    accepted: int
    rejected: int
    event_ids: list[UUID]

class QueuedResponse(BaseModel):
    event_id: UUID
    accepted_at: datetime
    status: str = "queued"


class EventStatusResponse(BaseModel):
    event_id: UUID
    status: Literal["accepted", "published", "processing", "processed", "failed"]
    accepted_at: datetime
    published_at: datetime | None = None
    processed_at: datetime | None = None
    retry_count: int
    failure_reason: str | None = None
