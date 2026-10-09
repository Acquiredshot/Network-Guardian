from app.main import app
from app.pages import render_pages
from fastapi.testclient import TestClient


def test_topology_is_linked_on_every_page():
    for html in render_pages().values():
        assert 'href="/topology"' in html


def test_topology_route_and_assets():
    with TestClient(app) as client:
        response = client.get("/topology")
        assert response.status_code == 200
        assert 'data-page="topology"' in response.text
        assert 'aria-current="page" href="/topology"' in response.text
        assert 'id="topologyGraph"' in response.text
        assert 'href="/incidents"' in response.text
        assert "not live packets" in response.text
        assert "NOT A WORKER HEARTBEAT" in response.text
        assert client.get("/static/pages/topology.js").status_code == 200


def test_topology_escapes_guardian_incident_report_destination():
    html = render_pages(network_guardian_dashboard_url="https://guardian.example/dashboard?q=1&x=2")["topology"]
    assert 'href="https://guardian.example/incidents"' in html
    assert "{{network_guardian_incidents_url}}" not in html
