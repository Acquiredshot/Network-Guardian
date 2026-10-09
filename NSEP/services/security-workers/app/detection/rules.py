from typing import Any

def detect(event: dict[str, Any]) -> list[dict[str, Any]]:
    payload = event.get("payload", {})
    detections: list[dict[str, Any]] = []
    if payload.get("failed_logins", 0) >= 5:
        detections.append({"rule": "BRUTE_FORCE", "severity": "high"})
    if event.get("event_type") in {"malware", "ransomware"}:
        detections.append({"rule": "MALWARE_ACTIVITY", "severity": "critical"})
    return detections
