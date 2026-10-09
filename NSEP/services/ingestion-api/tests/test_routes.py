import re
from datetime import UTC, datetime
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.api import routes
from app.api.routes import DependencyState
from app.messaging.rabbitmq import InMemoryPublisher
from shared.schemas import DependencyDiagnostic

client = TestClient(app)
app.state.dependencies = DependencyState(InMemoryPublisher())


def test_root_serves_soc_dashboard_and_assets():
    response = client.get("/")

    assert response.status_code == 200
    assert "Network Security Event Pipeline" in response.text
    assert "/static/dashboard.css" in response.text
    assert "/static/dashboard.js" in response.text
    assert client.get("/static/dashboard.css").status_code == 200
    assert client.get("/static/dashboard.js").status_code == 200


SOC_ROUTES = ["dashboard", "events", "threats", "ids", "ips", "explorer", "incidents", "reports"]


def test_root_redirects_to_dashboard():
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == "/dashboard"


@pytest.mark.parametrize("route", SOC_ROUTES)
def test_each_navigation_item_is_its_own_page(route):
    response = client.get(f"/{route}")

    assert response.status_code == 200
    assert f'data-page="{route}"' in response.text
    assert f'class="nav-link active" aria-current="page" href="/{route}"' in response.text
    assert response.text.count('aria-current="page"') == 1
    for other in SOC_ROUTES:
        assert f'href="/{other}"' in response.text
    assert 'class="nav-link" href="#' not in response.text
    assert "/static/core.js" in response.text
    for asset in re.findall(r'src="(/static/[^"]+)"', response.text):
        assert client.get(asset).status_code == 200
    if route != "dashboard":
        assert 'class="back-link" href="/dashboard"' in response.text


def test_ips_page_does_not_present_prevention_data():
    response = client.get("/ips")

    assert "NOT IMPLEMENTED" in response.text
    assert "NO TELEMETRY" in response.text


NEW_GROUPED_ROUTES = [
    "network-guardian", "network-guardian/devices", "network-guardian/events",
    "network-guardian/threats", "network-guardian/investigations",
    "zammad", "zammad/queues", "zammad/customers", "zammad/analytics",
    "hermes", "hermes/investigations", "hermes/actions", "hermes/activity",
    "admin/health", "admin/integrations", "admin/settings",
]


@pytest.mark.parametrize("route", NEW_GROUPED_ROUTES)
def test_every_new_grouped_route_is_a_real_page(route):
    response = client.get(f"/{route}")

    assert response.status_code == 200
    assert f'data-page="{route}"' in response.text
    assert response.text.count('aria-current="page"') == 1
    assert 'class="nav-link" href="#' not in response.text
    for asset in re.findall(r'src="(/static/[^"]+)"', response.text):
        assert client.get(asset).status_code == 200
    assert 'class="back-link" href="/dashboard"' in response.text


@pytest.mark.parametrize(
    ("route", "content"),
    [
        ("network-guardian", "Network Guardian's Event Fabric"),
        ("zammad", "Zammad ticket per new incident"),
        ("hermes", "Hermes Agent connects to NSEP's MCP server"),
    ],
)
def test_external_system_overviews_render_their_own_templates(route, content):
    response = client.get(f"/{route}")

    assert response.status_code == 200
    assert content in response.text
    assert "API NOT AVAILABLE" not in response.text


PLACEHOLDER_ROUTES = [
    "network-guardian/devices", "network-guardian/events", "network-guardian/threats", "network-guardian/investigations",
    "zammad/queues", "zammad/customers", "zammad/analytics",
    "hermes/investigations", "hermes/actions", "hermes/activity",
]


@pytest.mark.parametrize("route", PLACEHOLDER_ROUTES)
def test_placeholder_routes_never_fabricate_data(route):
    response = client.get(f"/{route}")

    assert "API NOT AVAILABLE" in response.text
    assert "not queryable from NSEP" in response.text


def test_dashboard_is_the_unified_landing_page_with_platform_links():
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert 'href="/network-guardian"' in response.text
    assert 'href="/zammad"' in response.text
    assert 'href="/hermes"' in response.text
    assert 'href="/admin/health"' in response.text


def test_group_pills_present_on_every_page():
    response = client.get("/events")

    for group_route in ["network-guardian", "zammad", "hermes", "admin/health"]:
        assert f'href="/{group_route}"' in response.text


def test_swagger_and_existing_api_reference_remain_available():
    swagger_response = client.get("/docs")
    reference_response = client.get("/api/docs")

    assert swagger_response.status_code == 200
    assert "swagger-ui" in swagger_response.text
    assert "/api/openapi.json" in swagger_response.text
    assert reference_response.status_code == 200
    assert "API Reference" in reference_response.text


@pytest.fixture(autouse=True)
def stub_event_persistence(monkeypatch):
    monkeypatch.setattr(routes, "record_event_accepted", lambda *_args: None)
    monkeypatch.setattr(routes, "update_event_status", lambda *_args: None)

EVENT = {
    "source": "firewall-01",
    "event_type": "login_failure",
    "occurred_at": datetime.now(UTC).isoformat(),
    "payload": {"failed_logins": 5},
    "metadata": {"region": "eastus"},
}

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_request_id_is_preserved_on_response():
    response = client.get("/api/health", headers={"X-Request-ID": "test-request-1"})

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-request-1"


def test_readiness_reports_dependency_state(monkeypatch):
    monkeypatch.setattr(
        routes,
        "probe_dependencies",
        lambda *_args: {
            name: DependencyDiagnostic(status="ready")
            for name in ("database", "broker", "cache")
        },
    )

    response = client.get("/api/readiness")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "services": {"database": "ready", "broker": "ready", "cache": "ready"},
    }


def test_diagnostics_reports_dependency_status_without_secrets(monkeypatch):
    monkeypatch.setattr(
        routes,
        "probe_dependencies",
        lambda *_args: {
            "database": DependencyDiagnostic(status="ready", latency_ms=1.2),
            "broker": DependencyDiagnostic(status="ready", latency_ms=2.3),
            "cache": DependencyDiagnostic(status="ready", latency_ms=0.8),
        },
    )

    response = client.get("/api/diagnostics")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "ingestion-api",
        "version": "0.1.0",
        "dependencies": {
            "database": {"status": "ready", "latency_ms": 1.2},
            "broker": {"status": "ready", "latency_ms": 2.3},
            "cache": {"status": "ready", "latency_ms": 0.8},
        },
    }


def test_dashboard_summary_uses_persisted_aggregate_data(monkeypatch):
    monkeypatch.setattr(
        routes,
        "load_dashboard_summary",
        lambda *_args: {
            "total_events": 12,
            "active_threats": 2,
            "active_incidents": 1,
            "test_event_count": 0,
            "test_active_incidents": 0,
            "test_active_detections": 0,
            "event_activity": [{"timestamp": "2026-09-26T04:00:00Z", "count": 3}],
            "active_detections_by_rule": [{"rule": "BRUTE_FORCE", "severity": "high", "count": 2}],
        },
    )

    response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    assert response.json()["total_events"] == 12
    assert response.json()["active_threats"] == 2
    assert response.json()["event_activity"][0]["count"] == 3


def test_event_search_returns_paged_records_and_forwards_filters(monkeypatch):
    received = {}

    def fake_list_events(_database_url, **kwargs):
        received.update(kwargs)
        return {
            "items": [{
                "event_id": "11111111-1111-1111-1111-111111111111",
                "source": "firewall-01",
                "event_type": "login_failure",
                "occurred_at": "2026-09-26T04:00:00Z",
                "accepted_at": "2026-09-26T04:00:01Z",
                "published_at": None,
                "processed_at": None,
                "status": "accepted",
                "retry_count": 0,
                "failure_reason": None,
                "payload": {"failed_logins": 5},
                "metadata": {},
                "severity": "high",
                "incident_id": "22222222-2222-2222-2222-222222222222",
                "detections": [{"rule": "BRUTE_FORCE", "severity": "high"}],
            }],
            "total": 1,
            "limit": 10,
            "offset": 0,
        }

    monkeypatch.setattr(routes, "list_events", fake_list_events)
    response = client.get("/api/v1/events?q=firewall&status=processed&severity=high&limit=10")

    assert response.status_code == 200
    assert response.json()["items"][0]["payload"]["failed_logins"] == 5
    assert response.json()["total"] == 1
    assert received["query"] == "firewall"
    assert received["status"] == "processed"
    assert received["severity"] == "high"


def test_detection_and_incident_lists_expose_persisted_records(monkeypatch):
    monkeypatch.setattr(
        routes,
        "list_detections",
        lambda *_args, **_kwargs: {"items": [], "total": 0, "limit": 25, "offset": 0},
    )
    monkeypatch.setattr(
        routes,
        "list_incidents",
        lambda *_args, **_kwargs: {"items": [], "total": 0, "limit": 25, "offset": 0},
    )

    detections = client.get("/api/v1/detections?severity=critical")
    incidents = client.get("/api/v1/incidents?status=open")

    assert detections.status_code == 200
    assert detections.json() == {"items": [], "total": 0, "limit": 25, "offset": 0}
    assert incidents.status_code == 200
    assert incidents.json() == {"items": [], "total": 0, "limit": 25, "offset": 0}


def test_incident_timeline_and_graph_use_existing_relationships(monkeypatch):
    incident_id = "22222222-2222-2222-2222-222222222222"
    monkeypatch.setattr(routes, "load_incident", lambda *_args: {"incident_id": incident_id})
    monkeypatch.setattr(
        routes,
        "get_incident_timeline",
        lambda *_args: [{
            "timestamp": "2026-09-26T04:00:00Z",
            "kind": "detection",
            "summary": "Detection: BRUTE_FORCE",
            "details": {"severity": "high"},
        }],
    )
    monkeypatch.setattr(
        routes,
        "get_incident_graph",
        lambda *_args: {
            "nodes": [{"id": "event:one", "kind": "event", "label": "firewall · login_failure", "details": {}}],
            "edges": [],
        },
    )

    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline")
    graph = client.get(f"/api/v1/incidents/{incident_id}/graph")

    assert timeline.status_code == 200
    assert timeline.json()[0]["kind"] == "detection"
    assert graph.status_code == 200
    assert graph.json()["nodes"][0]["kind"] == "event"


def test_dashboard_list_limits_are_bounded():
    assert client.get("/api/v1/events?limit=101").status_code == 422
    assert client.get("/api/v1/detections?offset=-1").status_code == 422


def test_event_status_is_queryable(monkeypatch):
    event_id = "11111111-1111-1111-1111-111111111111"
    monkeypatch.setattr(
        routes,
        "get_event_status",
        lambda *_args: {
            "event_id": event_id,
            "status": "processed",
            "accepted_at": "2026-09-26T04:00:00Z",
            "published_at": "2026-09-26T04:00:01Z",
            "processed_at": "2026-09-26T04:00:02Z",
            "retry_count": 0,
            "failure_reason": None,
        },
    )

    response = client.get(f"/api/v1/events/{event_id}")

    assert response.status_code == 200
    assert response.json()["status"] == "processed"


def test_incident_is_queryable(monkeypatch):
    incident_id = "22222222-2222-2222-2222-222222222222"
    monkeypatch.setattr(
        routes,
        "load_incident",
        lambda *_args: {
            "incident_id": incident_id,
            "status": "open",
            "risk": 75,
            "detections": [{"rule": "BRUTE_FORCE", "severity": "high"}],
            "timestamps": {"created_at": "2026-09-26T04:00:00Z"},
        },
    )

    response = client.get(f"/api/v1/incidents/{incident_id}")

    assert response.status_code == 200
    assert response.json()["risk"] == 75
    assert response.json()["detections"][0]["rule"] == "BRUTE_FORCE"


def test_event_is_normalized_and_queued():
    response = client.post("/api/v1/events", json=EVENT)
    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    assert len(response.json()["event_id"]) == 36

def test_invalid_event_uses_error_contract():
    response = client.post("/api/v1/events", json={"source": ""})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"

def test_batch_is_bounded():
    response = client.post("/api/v1/events/batch", json={"events": [EVENT] * 101})
    assert response.status_code == 422
