import importlib.util
import sys
from types import ModuleType, SimpleNamespace
from pathlib import Path

WORKER_APP = Path(__file__).parents[1] / "app"


def load_network_guardian_module():
    settings_module = ModuleType("app.settings")
    settings_module.settings = SimpleNamespace(
        network_guardian_enabled=True,
        network_guardian_intake_url="http://localhost:8080/api/event-fabric/intake",
        network_guardian_asset_id="nsep-pipeline",
        network_guardian_tenant_id="nsep-tenant",
    )
    original_settings_module = sys.modules.get("app.settings")
    sys.modules["app.settings"] = settings_module
    try:
        spec = importlib.util.spec_from_file_location(
            "worker_network_guardian_under_test",
            WORKER_APP / "integrations" / "network_guardian.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, settings_module.settings
    finally:
        if original_settings_module is None:
            sys.modules.pop("app.settings", None)
        else:
            sys.modules["app.settings"] = original_settings_module


class FakeResponse:
    ok = True

    def json(self):
        return {"ok": True, "row_id": 42, "graph_nodes": 3}


def test_push_incident_uses_configured_endpoint_and_envelope(monkeypatch):
    network_guardian, settings = load_network_guardian_module()
    monkeypatch.setattr(settings, "network_guardian_enabled", True)
    monkeypatch.setattr(settings, "network_guardian_intake_url", "http://ng-host:8080/api/event-fabric/intake")
    monkeypatch.setattr(settings, "network_guardian_asset_id", "nsep-pipeline")
    monkeypatch.setattr(settings, "network_guardian_tenant_id", "nsep-tenant")
    received = {}

    def fake_post(url, *, json, headers, timeout):
        received.update(url=url, payload=json, headers=headers, timeout=timeout)
        return FakeResponse()

    monkeypatch.setattr(network_guardian.requests, "post", fake_post)

    result = network_guardian.NetworkGuardianClient().push_incident(
        incident_id="11111111-1111-1111-1111-111111111111",
        event_id="22222222-2222-2222-2222-222222222222",
        source="test-source",
        event_type="brute_force",
        severity="high",
        risk=75,
        detections=[{"rule": "BRUTE_FORCE", "severity": "high"}],
    )

    assert result == {"ok": True, "row_id": 42, "graph_nodes": 3}
    assert received["url"] == "http://ng-host:8080/api/event-fabric/intake"
    assert received["payload"]["asset_id"] == "nsep-pipeline"
    assert received["payload"]["tenant_id"] == "nsep-tenant"
    assert received["payload"]["source"] == "NSEP"
    assert received["payload"]["severity"] == "high"
    assert received["payload"]["category"] == "threat"
    assert received["payload"]["payload"]["incident_id"] == "11111111-1111-1111-1111-111111111111"
    assert received["payload"]["payload"]["risk_score"] == 75


def test_push_incident_disabled_skips_request(monkeypatch):
    network_guardian, settings = load_network_guardian_module()
    monkeypatch.setattr(settings, "network_guardian_enabled", False)
    monkeypatch.setattr(
        network_guardian.requests,
        "post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("request should be disabled")),
    )

    client = network_guardian.NetworkGuardianClient()
    result = client.push_incident(
        incident_id="id",
        event_id="event",
        source="source",
        event_type="type",
        severity="low",
        risk=10,
        detections=[],
    )

    assert result is None


def test_push_incident_returns_none_on_http_failure(monkeypatch):
    network_guardian, settings = load_network_guardian_module()
    monkeypatch.setattr(settings, "network_guardian_enabled", True)

    class FailResponse:
        ok = False
        status_code = 500
        text = "internal error"

        def json(self):
            return {}

    monkeypatch.setattr(network_guardian.requests, "post", lambda *_args, **_kwargs: FailResponse())

    client = network_guardian.NetworkGuardianClient()
    result = client.push_incident(
        incident_id="id",
        event_id="event",
        source="source",
        event_type="type",
        severity="critical",
        risk=100,
        detections=[],
    )

    assert result is None
