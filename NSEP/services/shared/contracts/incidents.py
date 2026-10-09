from datetime import datetime
from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel

class IncidentResponse(BaseModel):
    incident_id: UUID
    status: Literal["open", "investigating", "resolved"]
    risk: int
    detections: list[dict[str, Any]]
    timestamps: dict[str, datetime]
