from typing import Any

from app.client import NSEPClient, NSEPClientError


def get_event(client: NSEPClient, event_id: str) -> dict[str, Any]:
    """Look up a single NSEP event by ID."""
    event = client.get_event(event_id)
    if event is None:
        return {"found": False, "event_id": event_id}
    return {"found": True, **event}


def get_incident(client: NSEPClient, incident_id: str) -> dict[str, Any]:
    """Look up a single NSEP incident by ID, including its risk score and detections."""
    incident = client.get_incident(incident_id)
    if incident is None:
        return {"found": False, "incident_id": incident_id}
    return {"found": True, **incident}


def search_events(
    client: NSEPClient,
    *,
    query: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    sort_by: str = "occurred_at",
    sort_order: str = "desc",
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """Search/filter NSEP events. All filters are optional and combine with AND."""
    return client.list_events(
        query=query,
        source=source,
        event_type=event_type,
        status=status,
        severity=severity,
        sort_by=sort_by,
        sort_order=sort_order,
        limit=limit,
        offset=offset,
    )


def get_detection_summary(
    client: NSEPClient,
    *,
    severity: str | None = None,
    rule: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """List NSEP detections, optionally filtered by severity or rule name."""
    return client.list_detections(
        severity=severity,
        rule=rule,
        limit=limit,
        offset=offset,
    )


def get_risk_score(client: NSEPClient, incident_id: str) -> dict[str, Any]:
    """Get the current risk score for an incident (reuses the incident record, no separate scoring logic)."""
    incident = client.get_incident(incident_id)
    if incident is None:
        return {"found": False, "incident_id": incident_id}
    return {
        "found": True,
        "incident_id": incident_id,
        "risk": incident.get("risk"),
        "status": incident.get("status"),
    }


def get_incident_timeline(client: NSEPClient, incident_id: str) -> dict[str, Any]:
    """Get the chronological event/detection/lifecycle timeline for an incident."""
    timeline = client.get_incident_timeline(incident_id)
    if timeline is None:
        return {"found": False, "incident_id": incident_id, "timeline": []}
    return {"found": True, "incident_id": incident_id, "timeline": timeline}


def investigate_incident(client: NSEPClient, incident_id: str) -> dict[str, Any]:
    """Composite read-only investigation view: incident + timeline + entity graph.

    Does not run any new detection/scoring logic -- only assembles existing
    NSEP API responses for a single incident.
    """
    incident = client.get_incident(incident_id)
    if incident is None:
        return {"found": False, "incident_id": incident_id}

    try:
        timeline = client.get_incident_timeline(incident_id) or []
    except NSEPClientError:
        timeline = []

    try:
        graph = client.get_incident_graph(incident_id)
    except NSEPClientError:
        graph = None

    return {
        "found": True,
        "incident": incident,
        "timeline": timeline,
        "graph": graph,
    }
