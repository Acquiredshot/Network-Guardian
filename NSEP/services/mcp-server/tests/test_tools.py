import importlib.util
import sys
from pathlib import Path
from types import ModuleType

MCP_APP = Path(__file__).parents[1] / "app"


class FakeClientError(Exception):
    pass


def load_tools_module():
    """Load app/tools.py in isolation, faking out app.client so no real HTTP
    client is required and this doesn't collide with ingestion-api's / security-workers' own "app" packages.
    """
    original_app = sys.modules.get("app")
    original_client = sys.modules.get("app.client")

    app_pkg = ModuleType("app")
    app_pkg.__path__ = []
    client_module = ModuleType("app.client")
    client_module.NSEPClient = object
    client_module.NSEPClientError = FakeClientError
    sys.modules["app"] = app_pkg
    sys.modules["app.client"] = client_module

    try:
        spec = importlib.util.spec_from_file_location(
            "mcp_server_tools_under_test",
            MCP_APP / "tools.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if original_app is None:
            sys.modules.pop("app", None)
        else:
            sys.modules["app"] = original_app
        if original_client is None:
            sys.modules.pop("app.client", None)
        else:
            sys.modules["app.client"] = original_client


class FakeNSEPClient:
    def __init__(self):
        self.calls = []

    def get_event(self, event_id):
        self.calls.append(("get_event", event_id))
        if event_id == "missing":
            return None
        return {"event_id": event_id, "status": "processed"}

    def get_incident(self, incident_id):
        self.calls.append(("get_incident", incident_id))
        if incident_id == "missing":
            return None
        return {"incident_id": incident_id, "status": "open", "risk": 75, "detections": []}

    def list_events(self, **params):
        self.calls.append(("list_events", params))
        return {"items": [{"event_id": "e1"}], "total": 1, "limit": params.get("limit"), "offset": params.get("offset")}

    def list_detections(self, **params):
        self.calls.append(("list_detections", params))
        return {"items": [{"rule": "BRUTE_FORCE", "severity": "high"}], "total": 1, "limit": params.get("limit"), "offset": params.get("offset")}

    def get_incident_timeline(self, incident_id):
        self.calls.append(("get_incident_timeline", incident_id))
        if incident_id == "missing":
            return None
        return [{"kind": "event_accepted"}, {"kind": "detection"}]

    def get_incident_graph(self, incident_id):
        self.calls.append(("get_incident_graph", incident_id))
        if incident_id == "missing":
            return None
        return {"nodes": [{"id": "n1"}], "edges": []}


def test_get_event_found_and_missing():
    tools = load_tools_module()
    client = FakeNSEPClient()

    found = tools.get_event(client, "e1")
    assert found == {"found": True, "event_id": "e1", "status": "processed"}

    missing = tools.get_event(client, "missing")
    assert missing == {"found": False, "event_id": "missing"}


def test_get_incident_found_and_missing():
    tools = load_tools_module()
    client = FakeNSEPClient()

    found = tools.get_incident(client, "i1")
    assert found["found"] is True
    assert found["risk"] == 75

    missing = tools.get_incident(client, "missing")
    assert missing == {"found": False, "incident_id": "missing"}


def test_search_events_passes_filters_through():
    tools = load_tools_module()
    client = FakeNSEPClient()

    result = tools.search_events(client, source="firewall", severity="high", limit=5, offset=10)

    assert result["total"] == 1
    assert client.calls[0][1]["source"] == "firewall"
    assert client.calls[0][1]["severity"] == "high"
    assert client.calls[0][1]["limit"] == 5
    assert client.calls[0][1]["offset"] == 10


def test_get_risk_score_reuses_incident_no_new_logic():
    tools = load_tools_module()
    client = FakeNSEPClient()

    result = tools.get_risk_score(client, "i1")

    assert result == {"found": True, "incident_id": "i1", "risk": 75, "status": "open"}
    assert client.calls == [("get_incident", "i1")]


def test_get_incident_timeline_missing():
    tools = load_tools_module()
    client = FakeNSEPClient()

    result = tools.get_incident_timeline(client, "missing")

    assert result == {"found": False, "incident_id": "missing", "timeline": []}


def test_investigate_incident_composes_three_reads():
    tools = load_tools_module()
    client = FakeNSEPClient()

    result = tools.investigate_incident(client, "i1")

    assert result["found"] is True
    assert result["incident"]["incident_id"] == "i1"
    assert len(result["timeline"]) == 2
    assert result["graph"]["nodes"] == [{"id": "n1"}]
    assert [c[0] for c in client.calls] == ["get_incident", "get_incident_timeline", "get_incident_graph"]


def test_investigate_incident_missing_incident_short_circuits():
    tools = load_tools_module()
    client = FakeNSEPClient()

    result = tools.investigate_incident(client, "missing")

    assert result == {"found": False, "incident_id": "missing"}
    assert client.calls == [("get_incident", "missing")]
