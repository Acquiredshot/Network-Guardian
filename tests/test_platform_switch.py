import pytest

from network_guardian.interface.dashboard import Dashboard


@pytest.mark.parametrize("tag", ["nav", "div"])
def test_platform_switch_uses_default_nsep_destination(monkeypatch, tag):
    monkeypatch.delenv("NSEP_DASHBOARD_URL", raising=False)
    html = Dashboard._inject_platform_switch(f'<{tag} class="nav"><a href="/">Dashboard</a></{tag}>')

    assert 'href="http://localhost:8000/dashboard">Switch to NSEP</a>' in html
    assert 'href="/">Dashboard</a>' in html
    assert 'target="_blank"' not in html


def test_platform_switch_escapes_configured_destination(monkeypatch):
    monkeypatch.setenv("NSEP_DASHBOARD_URL", "https://nsep.example/dashboard?a=1&b=2")
    html = Dashboard._inject_platform_switch('<nav class="nav"></nav>')

    assert 'href="https://nsep.example/dashboard?a=1&amp;b=2"' in html


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///dashboard.html", "", "http://localhost:99999"])
def test_platform_switch_rejects_invalid_destination(monkeypatch, url):
    monkeypatch.setenv("NSEP_DASHBOARD_URL", url)
    with pytest.raises(ValueError):
        Dashboard._inject_platform_switch('<nav class="nav"></nav>')


def test_platform_switch_is_present_in_rendered_dashboard(monkeypatch):
    monkeypatch.delenv("NSEP_DASHBOARD_URL", raising=False)
    dashboard = Dashboard.__new__(Dashboard)
    html = dashboard._page_index()

    assert html.count('class="platform-switch"') == 1
    assert "Switch to NSEP" in html


def test_navigation_links_topology_and_incident_reports(monkeypatch):
    monkeypatch.setenv("NSEP_DASHBOARD_URL", "http://127.0.0.1:18000/dashboard")
    html = Dashboard._inject_platform_switch('<nav class="nav"></nav>')
    assert 'href="http://127.0.0.1:18000/topology">Live Topology</a>' in html
    assert 'href="/incidents">Incident Reports</a>' in html


def test_incident_link_is_not_duplicated(monkeypatch):
    monkeypatch.delenv("NSEP_DASHBOARD_URL", raising=False)
    html = Dashboard._inject_platform_switch('<nav class="nav"><a href="/incidents">Incidents</a></nav>')
    assert html.count('href="/incidents"') == 1
