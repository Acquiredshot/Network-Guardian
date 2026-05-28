# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Unit Tests: Probe Defensive Scanner
"""

import pytest
from pathlib import Path

from network_guardian.agent.probe_defensive_scanner import ProbeDefensiveScanner
from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


class TestProbeDefensiveScanner:
    """Test defensive scanning for internal vulnerabilities."""

    def test_scanner_initialization(self, temp_dir):
        """Scanner initializes cleanly."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)
        assert scanner._data_dir == temp_dir
        assert len(scanner._scan_results) == 0

    def test_synthesize_http_payloads(self, temp_dir):
        """Scanner synthesizes HTTP test payloads."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._synthesize_payloads_for_service("http")

        assert len(payloads) > 0
        # Each entry should be a dict mapping injection_type -> payload
        for payload_dict in payloads:
            assert isinstance(payload_dict, dict)
            assert len(payload_dict) > 0

    def test_synthesize_sql_payloads(self, temp_dir):
        """Scanner synthesizes SQL test payloads."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._synthesize_payloads_for_service("sql")

        assert len(payloads) > 0
        # Should have UNION SELECT and sleep-based payloads
        sql_payloads = str(payloads).lower()
        assert "union" in sql_payloads or "select" in sql_payloads

    def test_synthesize_soap_payloads(self, temp_dir):
        """Scanner synthesizes SOAP test payloads."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._synthesize_payloads_for_service("soap")

        assert len(payloads) > 0

    def test_synthesize_ldap_payloads(self, temp_dir):
        """Scanner synthesizes LDAP test payloads."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._synthesize_payloads_for_service("ldap")

        assert len(payloads) > 0

    def test_is_vulnerable_sql_error(self, temp_dir):
        """Scanner detects SQL error responses as vulnerable."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        # SQL error response
        assert scanner._is_vulnerable(200, "MySQL Error: Syntax error") == True

    def test_is_vulnerable_exception_trace(self, temp_dir):
        """Scanner detects exception traces as vulnerable."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        # Python traceback
        assert scanner._is_vulnerable(200, "Traceback (most recent call last):") == True

    def test_is_vulnerable_java_error(self, temp_dir):
        """Scanner detects Java error responses as vulnerable."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        # Java exception
        assert scanner._is_vulnerable(200, "java.lang.NullPointerException") == True

    def test_is_not_vulnerable_403(self, temp_dir):
        """Scanner marks 403 responses as blocked (not vulnerable)."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        assert scanner._is_vulnerable(403, "Forbidden") == False
        assert scanner._is_vulnerable(403, "Access Denied") == False

    def test_is_not_vulnerable_clean_response(self, temp_dir):
        """Scanner marks clean responses as not vulnerable."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        assert scanner._is_vulnerable(200, "Welcome to the website") == False
        assert scanner._is_vulnerable(200, "Success") == False

    def test_is_not_vulnerable_no_content(self, temp_dir):
        """Scanner marks empty responses as inconclusive."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        assert scanner._is_vulnerable(200, None) == False
        assert scanner._is_vulnerable(200, "") == False

    def test_payload_for_http_contains_xss(self, temp_dir):
        """HTTP payload set includes XSS payloads."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._payloads_for_http()
        payload_str = str(payloads).lower()
        assert "<script>" in payload_str or "script" in payload_str

    def test_payload_for_http_contains_path_traversal(self, temp_dir):
        """HTTP payload set includes path traversal payloads."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._payloads_for_http()
        payload_str = str(payloads)
        assert ".." in payload_str

    def test_payload_for_sql_contains_union(self, temp_dir):
        """SQL payload set includes UNION SELECT."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._payloads_for_sql()
        payload_str = str(payloads).upper()
        assert "UNION" in payload_str

    def test_payload_for_sql_contains_sleep(self, temp_dir):
        """SQL payload set includes time-based payloads."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._payloads_for_sql()
        payload_str = str(payloads).upper()
        assert "SLEEP" in payload_str

    def test_scanner_persistence(self, temp_dir):
        """Scanner results persisted to disk."""
        from network_guardian.agent.probe_defensive_scanner import ScanResult

        scanner1 = ProbeDefensiveScanner(data_dir=temp_dir)
        result = ScanResult(
            target_ip="192.168.1.100",
            target_port=8080,
            service_type="http",
            injection_type="xss",
            payload="<script>test</script>",
            response_code=200,
            response_text="Vulnerable",
            was_blocked_by_firewall=False,
            is_vulnerable=True,
        )

        scanner1._scan_results["test"] = result
        scanner1._persist_scan_results()

        # New scanner should load from disk
        scanner2 = ProbeDefensiveScanner(data_dir=temp_dir)
        results = scanner2.get_vulnerable_endpoints()
        assert len(results) > 0

    def test_get_vulnerable_endpoints(self, temp_dir):
        """Scanner reports vulnerable endpoints."""
        from network_guardian.agent.probe_defensive_scanner import ScanResult

        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        # Add vulnerable result
        vuln_result = ScanResult(
            target_ip="192.168.1.100",
            target_port=8080,
            service_type="http",
            injection_type="xss",
            payload="<script>test</script>",
            response_code=200,
            response_text="Vulnerable",
            was_blocked_by_firewall=False,
            is_vulnerable=True,
        )

        # Add blocked result
        blocked_result = ScanResult(
            target_ip="192.168.1.101",
            target_port=8081,
            service_type="http",
            injection_type="xss",
            payload="<script>test</script>",
            response_code=403,
            response_text="Blocked",
            was_blocked_by_firewall=True,
            is_vulnerable=False,
        )

        scanner._scan_results["vuln"] = vuln_result
        scanner._scan_results["blocked"] = blocked_result

        vulnerable = scanner.get_vulnerable_endpoints()
        assert len(vulnerable) == 1
        assert vulnerable[0].target_ip == "192.168.1.100"

    def test_scanner_stats(self, temp_dir):
        """Scanner provides statistics."""
        from network_guardian.agent.probe_defensive_scanner import ScanResult

        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        # Add results
        scanner._scan_results["result1"] = ScanResult(
            target_ip="192.168.1.100",
            target_port=8080,
            service_type="http",
            injection_type="xss",
            payload="test",
            response_code=200,
            response_text="Vulnerable",
            was_blocked_by_firewall=False,
            is_vulnerable=True,
        )

        scanner._scan_results["result2"] = ScanResult(
            target_ip="192.168.1.101",
            target_port=8081,
            service_type="http",
            injection_type="xss",
            payload="test",
            response_code=403,
            response_text="Blocked",
            was_blocked_by_firewall=True,
            is_vulnerable=False,
        )

        stats = scanner.get_stats()
        assert stats["total_scans"] == 2
        assert stats["vulnerable_endpoints"] == 1
        assert stats["blocked_by_firewall"] == 1
        assert 0 <= stats["vulnerability_rate"] <= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
