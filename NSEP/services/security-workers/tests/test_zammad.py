import importlib.util
import sys
from types import ModuleType, SimpleNamespace
from pathlib import Path

WORKER_APP = Path(__file__).parents[1] / "app"


def load_zammad_module():
    settings_module = ModuleType("app.settings")
    settings_module.settings = SimpleNamespace(
        zammad_enabled=True,
        zammad_url="http://localhost:8080",
        zammad_api_token=None,
        zammad_group_id=1,
        zammad_customer_id=2,
    )
    original_settings_module = sys.modules.get("app.settings")
    sys.modules["app.settings"] = settings_module
    try:
        spec = importlib.util.spec_from_file_location(
            "worker_zammad_under_test",
            WORKER_APP / "integrations" / "zammad.py",
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
        return {"id": 4321, "number": "NSEP-4321"}


def test_create_ticket_uses_configured_endpoint_and_ticket_defaults(monkeypatch):
    zammad, settings = load_zammad_module()
    monkeypatch.setattr(settings, "zammad_enabled", True)
    monkeypatch.setattr(settings, "zammad_url", "http://zammad-nginx:8080/")
    monkeypatch.setattr(settings, "zammad_api_token", "unit-test-token")
    monkeypatch.setattr(settings, "zammad_group_id", 7)
    monkeypatch.setattr(settings, "zammad_customer_id", 9)
    received = {}

    def fake_post(url, *, headers, json, timeout):
        received.update(url=url, headers=headers, payload=json, timeout=timeout)
        return FakeResponse()

    monkeypatch.setattr(zammad.requests, "post", fake_post)

    result = zammad.ZammadClient().create_ticket(
        title="[NSEP] HIGH Security Incident",
        article_body="Test incident body",
        priority_id=3,
    )

    assert result == {"id": 4321, "number": "NSEP-4321"}
    assert received["url"] == "http://zammad-nginx:8080/api/v1/tickets"
    assert received["headers"]["Authorization"] == "Token token=unit-test-token"
    assert received["payload"]["group_id"] == 7
    assert received["payload"]["customer_id"] == 9
    assert received["payload"]["priority_id"] == 3


def test_create_ticket_can_be_disabled_or_skip_when_token_missing(monkeypatch):
    zammad, settings = load_zammad_module()
    monkeypatch.setattr(settings, "zammad_enabled", False)
    monkeypatch.setattr(settings, "zammad_api_token", "unit-test-token")
    monkeypatch.setattr(
        zammad.requests,
        "post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("request should be disabled")),
    )
    client = zammad.ZammadClient()
    assert client.create_ticket(title="test", article_body="test", priority_id=2) is None

    monkeypatch.setattr(settings, "zammad_enabled", True)
    monkeypatch.setattr(settings, "zammad_api_token", None)
    client = zammad.ZammadClient()
    assert client.create_ticket(title="test", article_body="test", priority_id=2) is None


def test_severity_to_priority_mapping():
    zammad, _settings = load_zammad_module()
    assert zammad.severity_to_priority("low") == 1
    assert zammad.severity_to_priority("medium") == 2
    assert zammad.severity_to_priority("high") == 3
    assert zammad.severity_to_priority("critical") == 3
