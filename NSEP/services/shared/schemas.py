from uuid import UUID
from pydantic import BaseModel

class HealthResponse(BaseModel):
    status: str
    services: dict[str, str] | None = None


class DependencyDiagnostic(BaseModel):
    status: str
    latency_ms: float | None = None


class DiagnosticsResponse(BaseModel):
    status: str
    service: str
    version: str
    dependencies: dict[str, DependencyDiagnostic]

class IncidentPath(BaseModel):
    incident_id: UUID
