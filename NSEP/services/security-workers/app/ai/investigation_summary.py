from typing import Any

class InvestigationSummary:
    def __init__(self, endpoint: str | None, api_key: str | None):
        self.enabled = bool(endpoint and api_key)

    def summarize(self, incident: dict[str, Any]) -> str | None:
        if not self.enabled:
            return None
        return f"Investigation summary for {incident.get('status', 'unknown')} incident; deterministic risk={incident.get('risk', 0)}."
