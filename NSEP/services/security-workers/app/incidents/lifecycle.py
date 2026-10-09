from typing import Any
from uuid import uuid4

def create_incident(event: dict[str, Any], detections: list[dict[str, Any]], risk: int) -> dict[str, Any]:
    return {
        "incident_id": str(uuid4()),
        "event_id": event["event_id"],
        "detections": detections,
        "risk": risk,
        "status": "open",
    }
