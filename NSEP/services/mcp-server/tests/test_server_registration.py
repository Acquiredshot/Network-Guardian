import asyncio
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

MCP_SERVICE_ROOT = Path(__file__).parents[1]
MCP_APP = MCP_SERVICE_ROOT / "app"

APP_MODULE_NAMES = ["app", "app.settings", "app.client", "app.tools", "app.server"]


def _load_submodule(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_real_server_module():
    """Load the real app/server.py (and its real settings/client/tools) as the
    "app" package, isolated from ingestion-api's and security-workers' own
    "app" packages via a save/restore of sys.modules.
    """
    saved = {name: sys.modules.get(name) for name in APP_MODULE_NAMES}
    for name in APP_MODULE_NAMES:
        sys.modules.pop(name, None)

    try:
        app_pkg = ModuleType("app")
        app_pkg.__path__ = [str(MCP_APP)]
        sys.modules["app"] = app_pkg

        _load_submodule("app.settings", MCP_APP / "settings.py")
        _load_submodule("app.client", MCP_APP / "client.py")
        _load_submodule("app.tools", MCP_APP / "tools.py")
        server_module = _load_submodule("app.server", MCP_APP / "server.py")
        return server_module
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod


class FakeNSEPClient:
    def get_event(self, event_id):
        return {"event_id": event_id, "status": "processed"}

    def get_incident(self, incident_id):
        return {"incident_id": incident_id, "status": "open", "risk": 42, "detections": []}

    def list_events(self, **params):
        return {"items": [], "total": 0, "limit": params.get("limit"), "offset": params.get("offset")}

    def list_detections(self, **params):
        return {"items": [], "total": 0, "limit": params.get("limit"), "offset": params.get("offset")}

    def get_incident_timeline(self, incident_id):
        return [{"kind": "event_accepted"}]

    def get_incident_graph(self, incident_id):
        return {"nodes": [], "edges": []}


def test_all_seven_tools_are_registered():
    server_module = load_real_server_module()

    tool_names = {tool.name for tool in asyncio.run(server_module.server.list_tools())}

    assert tool_names == {
        "get_event",
        "get_incident",
        "search_events",
        "get_detection_summary",
        "get_risk_score",
        "get_incident_timeline",
        "investigate_incident",
    }


def test_all_tools_are_marked_read_only():
    server_module = load_real_server_module()

    tools_list = asyncio.run(server_module.server.list_tools())

    for tool in tools_list:
        assert tool.annotations is not None, f"{tool.name} has no annotations"
        assert tool.annotations.read_only_hint is True, f"{tool.name} is not marked read-only"
        assert tool.annotations.destructive_hint is False, f"{tool.name} is not marked non-destructive"


def test_call_tool_get_incident_round_trips_through_real_server(monkeypatch):
    server_module = load_real_server_module()
    monkeypatch.setattr(server_module, "client", FakeNSEPClient())

    result = asyncio.run(server_module.server.call_tool("get_incident", {"incident_id": "i1"}))

    assert result.is_error is not True
    assert result.structured_content["found"] is True
    assert result.structured_content["risk"] == 42


def test_call_tool_investigate_incident_composes_reads(monkeypatch):
    server_module = load_real_server_module()
    monkeypatch.setattr(server_module, "client", FakeNSEPClient())

    result = asyncio.run(server_module.server.call_tool("investigate_incident", {"incident_id": "i1"}))

    assert result.is_error is not True
    assert result.structured_content["incident"]["incident_id"] == "i1"
    assert result.structured_content["timeline"] == [{"kind": "event_accepted"}]
    assert result.structured_content["graph"] == {"nodes": [], "edges": []}
