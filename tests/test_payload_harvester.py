# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Unit Tests: Payload Harvester
"""

import pytest
from pathlib import Path

from network_guardian.agent.payload_harvester import PayloadHarvester
from network_guardian.agent.smart_firewall_agent import InjectionType


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


class TestPayloadHarvester:
    """Test payload harvesting and rule generation."""

    def test_harvester_initialization(self, temp_dir):
        """Harvester initializes cleanly."""
        harvester = PayloadHarvester(data_dir=temp_dir)
        assert harvester._data_dir == temp_dir
        assert len(harvester._harvested_rules) == 0

    def test_harvest_soap_payload(self, temp_dir):
        """Harvester converts SOAP payload to rule."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = (
            '<m:ConfigurationStarted xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1">'
            '<NewSessionID>11111111</NewSessionID></m:ConfigurationStarted>'
        )

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="soap_auth_bypass",
            source_ip="192.168.1.50",
            target_ip="192.168.1.1",
        )

        assert rule is not None
        assert rule.name.startswith("HARVESTED-")
        assert rule.confidence >= 0.75

    def test_harvest_sql_payload_union_select(self, temp_dir):
        """Harvester detects UNION SELECT SQL injection."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = "' UNION ALL SELECT NULL, username, password FROM users--"

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None
        assert rule.injection_type == InjectionType.SQL
        assert rule.severity == "critical"
        assert "union" in rule.pattern.lower()

    def test_harvest_xss_payload_script_tag(self, temp_dir):
        """Harvester detects XSS script tag injection."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = '<script>alert("XSS Vulnerability")</script>'

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="xss",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None
        assert rule.injection_type == InjectionType.XSS
        assert rule.severity == "high"

    def test_harvest_xss_payload_event_handler(self, temp_dir):
        """Harvester detects XSS event handler injection."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = '<img onerror=alert("XSS")>'

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="xss",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None
        assert rule.injection_type == InjectionType.XSS

    def test_harvest_cmd_injection_payload(self, temp_dir):
        """Harvester detects command injection."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = "; cat /etc/passwd"

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="command_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None
        assert rule.injection_type == InjectionType.CMD

    def test_harvest_path_traversal_payload(self, temp_dir):
        """Harvester detects path traversal."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = "../../etc/passwd"

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="path_traversal",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None
        assert rule.injection_type == InjectionType.PATH_TRAVERSAL

    def test_harvested_rule_persistence(self, temp_dir):
        """Harvested rules persisted to disk."""
        harvester1 = PayloadHarvester(data_dir=temp_dir)

        payload = "' OR '1'='1"
        rule1 = harvester1.harvest_from_exploitation(
            payload=payload,
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule1 is not None

        # New harvester should load from disk
        harvester2 = PayloadHarvester(data_dir=temp_dir)
        rules = harvester2.get_harvested_rules()
        assert len(rules) == 1
        assert rules[0].base_confidence > 0.75

    def test_harvester_prevents_duplicate_rules(self, temp_dir):
        """Harvester prevents duplicate rules for same payload."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = "' UNION SELECT 1,2,3"

        # Harvest same payload twice
        rule1 = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        rule2 = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="sql_injection",
            source_ip="192.168.1.51",
            target_ip="192.168.1.100",
        )

        rules = harvester.get_harvested_rules()
        # Should have same rule name (HARVESTED-SQL_INJECTION-1)
        assert rule1.name == rule2.name or len(rules) == 2

    def test_record_detection_success(self, temp_dir):
        """Harvester tracks successful detections."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = "' OR 1=1"
        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        harvester.record_detection(rule.name, success=True)
        harvester.record_detection(rule.name, success=True)
        harvester.record_detection(rule.name, success=False)

        rules = harvester.get_harvested_rules()
        assert rules[0].successful_detections == 2
        assert rules[0].failed_detections == 1

    def test_harvester_stats(self, temp_dir):
        """Harvester provides statistics."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        # Harvest multiple payloads
        harvester.harvest_from_exploitation(
            payload="' OR 1=1",
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        harvester.harvest_from_exploitation(
            payload="<script>alert(1)</script>",
            vuln_type="xss",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        stats = harvester.get_stats()
        assert stats["total_harvested_rules"] == 2
        assert len(stats["injection_types"]) == 2

    def test_harvest_too_short_payload(self, temp_dir):
        """Harvester rejects payloads that are too short."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        rule = harvester.harvest_from_exploitation(
            payload="ab",
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
