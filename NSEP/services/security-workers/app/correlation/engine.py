from typing import Any

def correlate(event: dict[str, Any], detections: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not detections:
        return None
    return {"source": event.get("source"), "rules": [item["rule"] for item in detections]}
