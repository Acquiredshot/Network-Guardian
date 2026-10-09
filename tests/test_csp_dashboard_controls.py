from html.parser import HTMLParser

import pytest

from network_guardian.interface._fleet import get_fleet_page
from network_guardian.interface.dashboard import Dashboard


class HandlerParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        assert not any(name.startswith("on") for name, _ in attrs)


@pytest.mark.parametrize("method", ["_page_reports", "_page_incidents"])
def test_report_pages_use_nonce_script_listeners_instead_of_inline_handlers(method):
    dashboard = Dashboard.__new__(Dashboard)
    response = getattr(dashboard, method)()
    body = response.split("\r\n\r\n", 1)[1]
    HandlerParser().feed(body)

    assert "onclick=" not in body
    assert "addEventListener" in body
    assert f'nonce="{Dashboard._csp_nonce}"' in body
    assert "script-src 'nonce-" in response


def test_fleet_cards_and_close_button_use_csp_compatible_listeners():
    body = get_fleet_page("test-nonce")
    HandlerParser().feed(body)

    assert "onclick=" not in body
    assert "data-agent-id=" in body
    assert "addEventListener('click',closeDetail)" in body
    assert "showAgent(card.dataset.agentId)" in body
