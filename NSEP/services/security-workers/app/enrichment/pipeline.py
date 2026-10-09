from typing import Any

def enrich(event: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(event)
    enriched["normalized_source"] = str(event.get("source", "")).lower()
    return enriched
