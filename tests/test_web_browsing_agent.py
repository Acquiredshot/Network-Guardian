# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
"""
Tests for network_guardian.agent.web_browsing_agent
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from network_guardian.agent.web_browsing_agent import (
    SafeWebBrowsingAgent,
    ThreatSignal,
    UrlCategory,
    UrlVerdict,
    _combined_confidence,
    _domain_in_list,
    _extract_hostname,
    _is_private_address,
    _threat_score,
    _verdict_category,
)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def make_agent(tmp_path: Path, fetch_content: bool = False) -> SafeWebBrowsingAgent:
    return SafeWebBrowsingAgent(
        event_bus=None,
        ips=None,
        data_dir=tmp_path,
        auto_block=False,
        fetch_content=fetch_content,
    )


# ---------------------------------------------------------------------------
# Unit: pure helpers
# ---------------------------------------------------------------------------

class TestExtractHostname:
    def test_simple_url(self):
        assert _extract_hostname("https://example.com/path") == "example.com"

    def test_subdomain(self):
        assert _extract_hostname("http://sub.evil.com/page?x=1") == "sub.evil.com"

    def test_with_port(self):
        assert _extract_hostname("https://example.com:8443/api") == "example.com"

    def test_ip_address(self):
        assert _extract_hostname("http://192.168.1.1/admin") == "192.168.1.1"

    def test_uppercase_scheme_lowercased(self):
        # urlparse lowercases the hostname
        assert _extract_hostname("HTTPS://EXAMPLE.COM/") == "example.com"

    def test_invalid_returns_none(self):
        assert _extract_hostname("not a url at all !!!") is None


class TestDomainInList:
    def test_exact_match(self):
        assert _domain_in_list("evil.com", ["evil.com"])

    def test_subdomain_wildcard(self):
        assert _domain_in_list("sub.evil.com", ["evil.com"])
        assert _domain_in_list("deep.sub.evil.com", ["evil.com"])

    def test_no_false_positive(self):
        assert not _domain_in_list("notevil.com", ["evil.com"])
        assert not _domain_in_list("evil.com.au", ["evil.com"])

    def test_case_insensitive(self):
        assert _domain_in_list("Evil.COM", ["evil.com"])

    def test_wildcard_entry_syntax(self):
        assert _domain_in_list("sub.evil.com", ["*.evil.com"])

    def test_empty_list(self):
        assert not _domain_in_list("example.com", [])


class TestIsPrivateAddress:
    def test_localhost_name(self):
        assert _is_private_address("localhost")

    def test_loopback_ip(self):
        assert _is_private_address("127.0.0.1")

    def test_rfc1918(self):
        assert _is_private_address("192.168.1.1")
        assert _is_private_address("10.0.0.1")
        assert _is_private_address("172.16.0.1")

    def test_ipv6_loopback(self):
        assert _is_private_address("::1")

    def test_public_ip_not_private(self):
        assert not _is_private_address("8.8.8.8")

    def test_dotlocal(self):
        assert _is_private_address("mydevice.local")


class TestCombinedConfidence:
    def test_empty(self):
        assert _combined_confidence([]) == 0.0

    def test_single(self):
        s = ThreatSignal("x", "high", 0.8, "")
        assert _combined_confidence([s]) == pytest.approx(0.8, abs=1e-4)

    def test_two_signals(self):
        signals = [
            ThreatSignal("a", "high", 0.6, ""),
            ThreatSignal("b", "high", 0.5, ""),
        ]
        # 1 - (1-0.6)*(1-0.5) = 1 - 0.4*0.5 = 0.8
        assert _combined_confidence(signals) == pytest.approx(0.8, abs=1e-4)

    def test_capped_at_one(self):
        signals = [ThreatSignal("x", "critical", 1.0, "")]
        assert _combined_confidence(signals) == pytest.approx(1.0, abs=1e-4)


class TestThreatScore:
    def test_no_signals_zero(self):
        assert _threat_score([]) == 0.0

    def test_single_critical(self):
        s = ThreatSignal("x", "critical", 1.0, "")
        assert _threat_score([s]) == pytest.approx(100.0, abs=1e-1)

    def test_single_medium(self):
        s = ThreatSignal("x", "medium", 1.0, "")
        assert _threat_score([s]) == pytest.approx(40.0, abs=1e-1)

    def test_mixed(self):
        signals = [
            ThreatSignal("a", "high", 0.9, ""),
            ThreatSignal("b", "medium", 0.5, ""),
        ]
        score = _threat_score(signals)
        assert 0 < score <= 100


class TestVerdictCategory:
    def test_empty_is_safe(self):
        assert _verdict_category([]) == UrlCategory.SAFE

    def test_critical_is_malicious(self):
        assert _verdict_category([ThreatSignal("x", "critical", 0.9, "")]) == UrlCategory.MALICIOUS

    def test_high_is_malicious(self):
        assert _verdict_category([ThreatSignal("x", "high", 0.7, "")]) == UrlCategory.MALICIOUS

    def test_medium_is_suspicious(self):
        assert _verdict_category([ThreatSignal("x", "medium", 0.5, "")]) == UrlCategory.SUSPICIOUS


# ---------------------------------------------------------------------------
# Unit: SafeWebBrowsingAgent — list checks (no network)
# ---------------------------------------------------------------------------

class TestAgentListChecks:
    def test_blocklist_hit(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("https://malware.example.com/path")
        assert v.category == UrlCategory.BLOCKED
        assert v.action_taken == "blocked"
        assert agent.get_stats()["total_blocked"] == 1

    def test_allowlist_hit(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("https://github.com/some/repo")
        assert v.category == UrlCategory.TRUSTED
        assert v.action_taken == "none"

    def test_private_ip_skipped(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("http://127.0.0.1/admin")
        assert v.category == UrlCategory.SKIPPED
        assert "SSRF" in (v.error or "")

    def test_localhost_skipped(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("http://localhost:8080/")
        assert v.category == UrlCategory.SKIPPED

    def test_non_http_scheme_skipped(self, tmp_path):
        agent = make_agent(tmp_path)
        for scheme in ("ftp://", "file:///", "javascript:"):
            v = agent.check_url(scheme + "example.com")
            assert v.category == UrlCategory.SKIPPED, f"Expected SKIPPED for {scheme}"

    def test_unparseable_url_error(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("https://")
        assert v.category in (UrlCategory.ERROR, UrlCategory.SKIPPED)

    def test_no_fetch_unknown_domain_is_safe(self, tmp_path):
        agent = make_agent(tmp_path, fetch_content=False)
        v = agent.check_url("https://some-unknown-site.org/page")
        assert v.category == UrlCategory.SAFE

    def test_verdict_id_unique(self, tmp_path):
        agent = make_agent(tmp_path)
        v1 = agent.check_url("https://github.com/")
        v2 = agent.check_url("https://google.com/")
        assert v1.verdict_id != v2.verdict_id

    def test_elapsed_ms_populated(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("https://github.com/")
        assert v.elapsed_ms >= 0


# ---------------------------------------------------------------------------
# Unit: domain list management
# ---------------------------------------------------------------------------

class TestDomainListManagement:
    def test_add_and_match_blocklist(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.add_to_blocklist("evil.com")
        v = agent.check_url("https://sub.evil.com/page")
        assert v.category == UrlCategory.BLOCKED

    def test_remove_from_blocklist(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.add_to_blocklist("evil.com")
        assert agent.remove_from_blocklist("evil.com") is True
        v = agent.check_url("https://evil.com/page")
        assert v.category != UrlCategory.BLOCKED

    def test_remove_nonexistent_returns_false(self, tmp_path):
        agent = make_agent(tmp_path)
        assert agent.remove_from_blocklist("notlisted.com") is False

    def test_add_and_match_allowlist(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.add_to_allowlist("trusted-corp.com")
        v = agent.check_url("https://trusted-corp.com/login")
        assert v.category == UrlCategory.TRUSTED

    def test_remove_from_allowlist(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.add_to_allowlist("trusted-corp.com")
        assert agent.remove_from_allowlist("trusted-corp.com") is True

    def test_no_duplicates_blocklist(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.add_to_blocklist("dupe.com")
        agent.add_to_blocklist("dupe.com")
        assert agent._blocklist.count("dupe.com") == 1

    def test_lists_persisted_to_disk(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.add_to_blocklist("persist-test.com")
        data = json.loads((tmp_path / "domain_lists.json").read_text())
        assert "persist-test.com" in data["blocklist"]

    def test_lists_loaded_on_init(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.add_to_blocklist("reload-test.com")
        # New instance same dir should reload
        agent2 = make_agent(tmp_path)
        assert "reload-test.com" in agent2._blocklist


# ---------------------------------------------------------------------------
# Unit: stats and history
# ---------------------------------------------------------------------------

class TestStatsAndHistory:
    def test_total_checked_increments(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.check_url("https://github.com/")
        agent.check_url("https://google.com/")
        assert agent.get_stats()["total_checked"] == 2

    def test_total_blocked_counts_blocklist(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.check_url("https://malware.example.com/")
        agent.check_url("https://phishing.example.com/")
        assert agent.get_stats()["total_blocked"] == 2

    def test_verdict_history_appended(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.check_url("https://github.com/")
        assert len(agent._verdict_history) == 1

    def test_verdict_history_capped_at_1000(self, tmp_path):
        agent = make_agent(tmp_path)
        # Inject 1100 fake entries
        agent._verdict_history = [{"category": "safe", "hostname": f"h{i}.com",
                                    "threat_score": 0, "timestamp": "2026-01-01T00:00:00+00:00",
                                    "url": f"https://h{i}.com"} for i in range(1100)]
        agent.check_url("https://github.com/")
        assert len(agent._verdict_history) <= 1000

    def test_dashboard_summary_keys(self, tmp_path):
        agent = make_agent(tmp_path)
        summary = agent.dashboard_summary()
        for key in ("status", "total_checked", "total_blocked", "total_malicious",
                    "blocklist_size", "allowlist_size", "top_malicious_hosts", "last_verdict"):
            assert key in summary, f"Missing key: {key}"

    def test_category_counts_in_stats(self, tmp_path):
        agent = make_agent(tmp_path)
        agent.check_url("https://github.com/")         # trusted
        agent.check_url("https://malware.example.com/")  # blocked
        stats = agent.get_stats()
        assert stats["category_counts"].get("trusted", 0) >= 1
        assert stats["category_counts"].get("blocked", 0) >= 1


# ---------------------------------------------------------------------------
# Unit: content signal detection (no HTTP — inject fake content)
# ---------------------------------------------------------------------------

class TestContentSignalDetection:
    def _detect(self, agent: SafeWebBrowsingAgent, text: str = "",
                html: str = "", url: str = "https://example.com") -> list[ThreatSignal]:
        return agent._detect_signals(text, html, url)

    def test_phishing_verify_account(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Please verify your account to continue.")
        names = [s.name for s in signals]
        assert "phishing_verify_account" in names

    def test_phishing_account_suspended(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Your account has been suspended.")
        assert any("suspended" in s.name for s in signals)

    def test_malware_keyword(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Download this free ransomware removal tool.")
        assert any(s.name == "malware_keyword" for s in signals)

    def test_drive_by_download(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Uses silent install to run in the background.")
        assert any(s.name == "drive_by_download" for s in signals)

    def test_js_eval_unescape(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, html="<script>eval(unescape('%3Cscript%3E'));</script>")
        assert any(s.name == "js_eval_unescape" for s in signals)

    def test_js_eval_atob(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, html='<script>eval(atob("aGVsbG8="));</script>')
        assert any(s.name == "js_eval_atob" for s in signals)

    def test_hidden_iframe(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, html='<iframe src="http://evil.com" style="display:none"></iframe>')
        assert any(s.name == "hidden_iframe" for s in signals)

    def test_cryptominer_coinhive(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Powered by CoinHive mining solution.")
        assert any(s.name == "cryptominer_known" for s in signals)

    def test_exploit_kit_language(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Uses heap spray and shellcode to exploit browsers.")
        assert any(s.name == "exploit_kit_language" for s in signals)

    def test_scam_prize(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Congratulations! You have won a free iPhone!")
        assert any(s.name == "scam_prize" for s in signals)

    def test_clean_content_no_signals(self, tmp_path):
        agent = make_agent(tmp_path)
        signals = self._detect(agent, text="Welcome to our homepage. We sell gardening supplies.")
        assert signals == []

    def test_no_duplicate_signals(self, tmp_path):
        agent = make_agent(tmp_path)
        # Repeat the same keyword multiple times
        signals = self._detect(agent, text="ransomware ransomware ransomware")
        names = [s.name for s in signals]
        assert len(names) == len(set(names)), "Duplicate signals found"


# ---------------------------------------------------------------------------
# Unit: IPS auto-block integration
# ---------------------------------------------------------------------------

class TestIpsAutoBlock:
    def test_malicious_verdict_calls_ips_block(self, tmp_path):
        mock_ips = MagicMock()
        agent = SafeWebBrowsingAgent(
            event_bus=None, ips=mock_ips,
            data_dir=tmp_path, auto_block=True, fetch_content=False,
        )
        # Manually mark a domain malicious via blocklist to get BLOCKED verdict
        agent.add_to_blocklist("ips-test.com")
        agent.check_url("https://ips-test.com/")
        # BLOCKED path takes action_taken="blocked" but doesn't call IPS
        # (blocklist blocks don't escalate to IPS — they're already list-managed)
        # Test that auto_block=True is wired; trigger MALICIOUS via content
        # by patching _fetch_and_analyze
        with patch.object(agent, "_fetch_and_analyze",
                          return_value=([ThreatSignal("malware_keyword", "critical", 0.95, "bad")], None)):
            agent.fetch_content = True
            v = agent.check_url("https://unknown-malicious-site.com/")
        assert v.category == UrlCategory.MALICIOUS
        mock_ips.block_ip.assert_called_once()

    def test_auto_block_false_skips_ips(self, tmp_path):
        mock_ips = MagicMock()
        agent = SafeWebBrowsingAgent(
            event_bus=None, ips=mock_ips,
            data_dir=tmp_path, auto_block=False, fetch_content=False,
        )
        with patch.object(agent, "_fetch_and_analyze",
                          return_value=([ThreatSignal("malware_keyword", "critical", 0.95, "bad")], None)):
            agent.fetch_content = True
            v = agent.check_url("https://no-autoblock-site.com/")
        assert v.category == UrlCategory.MALICIOUS
        mock_ips.block_ip.assert_not_called()


# ---------------------------------------------------------------------------
# Unit: event bus publishing
# ---------------------------------------------------------------------------

class TestEventBusPublishing:
    def test_event_published_for_unknown_domain(self, tmp_path):
        mock_bus = MagicMock()
        agent = SafeWebBrowsingAgent(
            event_bus=mock_bus, ips=None,
            data_dir=tmp_path, auto_block=False, fetch_content=False,
        )
        agent.check_url("https://some-unknown-site.org/")
        mock_bus.publish.assert_called_once()

    def test_event_published_for_blocklist_hit(self, tmp_path):
        mock_bus = MagicMock()
        agent = SafeWebBrowsingAgent(
            event_bus=mock_bus, ips=None,
            data_dir=tmp_path, auto_block=False, fetch_content=False,
        )
        agent.check_url("https://malware.example.com/")
        mock_bus.publish.assert_called_once()

    def test_no_event_for_allowlist_hit(self, tmp_path):
        """Allowlist hits return early — no event published."""
        mock_bus = MagicMock()
        agent = SafeWebBrowsingAgent(
            event_bus=mock_bus, ips=None,
            data_dir=tmp_path, auto_block=False, fetch_content=False,
        )
        agent.check_url("https://github.com/")
        mock_bus.publish.assert_not_called()


# ---------------------------------------------------------------------------
# Integration: UrlVerdict serialisation
# ---------------------------------------------------------------------------

class TestUrlVerdictSerialization:
    def test_to_dict_contains_expected_keys(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("https://malware.example.com/")
        d = v.to_dict()
        for key in ("verdict_id", "url", "hostname", "category",
                    "threat_score", "confidence", "signals",
                    "action_taken", "elapsed_ms", "timestamp"):
            assert key in d, f"Missing key: {key}"

    def test_category_is_string_not_enum(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("https://malware.example.com/")
        d = v.to_dict()
        assert isinstance(d["category"], str)

    def test_signals_are_dicts(self, tmp_path):
        agent = make_agent(tmp_path)
        v = agent.check_url("https://malware.example.com/")
        d = v.to_dict()
        for s in d["signals"]:
            assert isinstance(s, dict)
            assert "name" in s and "severity" in s
