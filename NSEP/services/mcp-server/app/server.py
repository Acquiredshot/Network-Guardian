import logging
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from app import tools
from app.client import NSEPClient
from app.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nsep_mcp.server")

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)

server = MCPServer(
    name="nsep-mcp",
    instructions=(
        "Read-only investigation interface over the Network Security Event Pipeline (NSEP). "
        "All tools call NSEP's existing ingestion-api endpoints -- no detection, scoring, "
        "or incident logic is duplicated here, and no tool can create/modify/delete data."
    ),
)

client = NSEPClient()


@server.tool(annotations=READ_ONLY)
def get_event(event_id: str) -> dict[str, Any]:
    """Look up a single NSEP event by its event_id."""
    return tools.get_event(client, event_id)


@server.tool(annotations=READ_ONLY)
def get_incident(incident_id: str) -> dict[str, Any]:
    """Look up a single NSEP incident by its incident_id, including risk score and detections."""
    return tools.get_incident(client, incident_id)


@server.tool(annotations=READ_ONLY)
def search_events(
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
    """Search/filter NSEP events by source, type, status, severity, or free-text query."""
    return tools.search_events(
        client,
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


@server.tool(annotations=READ_ONLY)
def get_detection_summary(
    severity: str | None = None,
    rule: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """List NSEP detections, optionally filtered by severity or rule name."""
    return tools.get_detection_summary(client, severity=severity, rule=rule, limit=limit, offset=offset)


@server.tool(annotations=READ_ONLY)
def get_risk_score(incident_id: str) -> dict[str, Any]:
    """Get the current risk score and status for an NSEP incident."""
    return tools.get_risk_score(client, incident_id)


@server.tool(annotations=READ_ONLY)
def get_incident_timeline(incident_id: str) -> dict[str, Any]:
    """Get the chronological timeline (events, detections, lifecycle changes) for an incident."""
    return tools.get_incident_timeline(client, incident_id)


@server.tool(annotations=READ_ONLY)
def investigate_incident(incident_id: str) -> dict[str, Any]:
    """Composite investigation view: incident details + timeline + entity graph for one incident."""
    return tools.investigate_incident(client, incident_id)


def main() -> None:
    logger.info(
        "nsep_mcp_starting",
        extra={"transport": settings.mcp_transport, "nsep_api_base_url": settings.nsep_api_base_url},
    )
    if settings.mcp_transport == "streamable-http":
        server.run(transport="streamable-http", host=settings.mcp_host, port=settings.mcp_port)
    elif settings.mcp_transport == "sse":
        server.run(transport="sse", host=settings.mcp_host, port=settings.mcp_port)
    else:
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
