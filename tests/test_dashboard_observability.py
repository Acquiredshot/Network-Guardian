from network_guardian.interface.dashboard import Dashboard, _TMPL_INDEX


def test_dashboard_root_page_uses_observability_language():
    assert "PakShield" in _TMPL_INDEX
    assert "Mask" in _TMPL_INDEX
    assert "Network Traffic" in _TMPL_INDEX
    assert "Heat Map" in _TMPL_INDEX


def test_dashboard_shell_applies_to_tab_pages_and_telemetry():
    ids_html = Dashboard._page_ids.__func__(Dashboard.__new__(Dashboard)) if hasattr(Dashboard._page_ids, '__func__') else Dashboard._page_ids(Dashboard.__new__(Dashboard))
    reports_html = Dashboard._page_reports.__func__(Dashboard.__new__(Dashboard)) if hasattr(Dashboard._page_reports, '__func__') else Dashboard._page_reports(Dashboard.__new__(Dashboard))

    for html in (ids_html, reports_html):
        assert "--ng-bg" in html
        assert "PakShield" in html or "Threat" in html
        assert "data-kpi=\"network-traffic\"" in html or "refreshDashboardTelemetry" in html
        assert "feature-grid" in html or "graph-stage" in html

    assert "fetch('/api/security-graph/summary')" in ids_html
    assert "fetch('/api/ids/stats')" in ids_html
    assert "fetch('/api/ips/stats')" in ids_html


def test_dashboard_tab_pages_share_soc_visual_language():
    explorer_html = Dashboard._page_explorer.__func__(Dashboard.__new__(Dashboard)) if hasattr(Dashboard._page_explorer, '__func__') else Dashboard._page_explorer(Dashboard.__new__(Dashboard))
    incidents_html = Dashboard._page_incidents.__func__(Dashboard.__new__(Dashboard)) if hasattr(Dashboard._page_incidents, '__func__') else Dashboard._page_incidents(Dashboard.__new__(Dashboard))
    security_html = Dashboard._page_security.__func__(Dashboard.__new__(Dashboard)) if hasattr(Dashboard._page_security, '__func__') else Dashboard._page_security(Dashboard.__new__(Dashboard))

    for html in (explorer_html, incidents_html, security_html):
        assert "--ng-bg" in html
        assert "feature-grid" in html or "graph-stage" in html or "Threat Detection" in html
        assert "nav a.active" in html or "Observability Core" in html
