from html import escape

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.pages import PAGES, render_pages


def test_every_page_has_combined_dashboard_return_button():
    pages = render_pages()

    assert set(pages) == {page.route for page in PAGES}
    for html in pages.values():
        assert html.count('class="nav-link platform-return"') == 1
        assert 'href="http://localhost:8080/">Switch to PakShield / Network Guardian</a>' in html
        assert "{{network_guardian_dashboard_url}}" not in html


def test_custom_dashboard_url_is_escaped_in_every_page():
    url = "https://platform.example/dashboard?view=security&tenant=nsep"

    for html in render_pages(network_guardian_dashboard_url=url).values():
        assert f'href="{escape(url, quote=True)}">Switch to PakShield / Network Guardian</a>' in html


def test_dashboard_url_is_configured_from_environment(monkeypatch):
    monkeypatch.setenv("NETWORK_GUARDIAN_DASHBOARD_URL", "https://platform.example/")
    monkeypatch.setenv("NETWORK_GUARDIAN_ENABLED", "false")
    settings = Settings(_env_file=None)

    assert str(settings.network_guardian_dashboard_url) == "https://platform.example/"
    assert settings.network_guardian_enabled is False


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///dashboard.html", ""])
def test_dashboard_url_rejects_invalid_configuration(url):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, network_guardian_dashboard_url=url)
