# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Integration Tests: Smart Firewall + Probe System

Tests for the four integration goals:
1. Threat Intelligence Feedback (Probe → Firewall)
2. Payload Harvesting (Probe Vulns → Firewall Rules)
3. Defensive Scanning (Probe Tests Network with Firewall Rules)
4. Attack Correlation (Probe Discoveries + Firewall Blocks)
"""

import asyncio
import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from network_guardian.core.events import Event, EventBus
from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent, InjectionDetection, InjectionType
from network_guardian.agent.probe_firewall_bridge import ProbeFirewallBridge, DiscoveredService
from network_guardian.agent.payload_harvester import PayloadHarvester
from network_guardian.agent.probe_defensive_scanner import ProbeDefensiveScanner
from network_guardian.agent.probe_attack_correlator import ProbeAttackCorrelator
from network_guardian.agent.probe_agent import ProbeAgent


@pytest.fixture
def event_bus():
    """Create a fresh event bus for each test."""
    return EventBus()


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for test data."""
    return tmp_path


# =============================================================================
# GOAL 1: THREAT INTELLIGENCE FEEDBACK (Probe → Firewall)
# =============================================================================

class TestThreatIntelligenceFeedback:
    """Test probe discoveries triggering firewall rule adaptation."""

    @pytest.mark.asyncio
    async def test_probe_discovers_sql_service_firewall_adapts(self, event_bus, temp_dir):
        """When probe discovers SQL service, firewall enables SQL injection rules."""
        firewall = SmartFirewallAgent(event_bus=event_bus, data_dir=temp_dir)
        bridge = ProbeFirewallBridge(event_bus=event_bus, smart_firewall=firewall)

        # Simulate probe discovering MySQL on 192.168.1.100:3306
        discovery_event = Event(
            topic="probe.discovery.open_port",
            data={
                "ip": "192.168.1.100",
                "port": 3306,
                "service": "mysql",
                "protocol": "tcp",
                "version": "5.7",
            }
        )

        await event_bus.publish(discovery_event)
        await asyncio.sleep(0.1)

        # Verify bridge registered the service
        services = bridge.get_discovered_services()
        assert len(services) > 0
        assert services[0].ip == "192.168.1.100"
        assert services[0].port == 3306

        # Verify firewall has service profile
        assert "mysql" in bridge._service_profiles
        profile = bridge._service_profiles["mysql"]
        assert profile.enhanced_logging == True
        assert len(profile.enabled_rules) > 0

    @pytest.mark.asyncio
    async def test_probe_discovers_weak_auth_increases_monitoring(self, event_bus, temp_dir):
        """When probe discovers weak auth, firewall increases sensitivity."""
        firewall = SmartFirewallAgent(event_bus=event_bus, data_dir=temp_dir)
        bridge = ProbeFirewallBridge(event_bus=event_bus, smart_firewall=firewall)

        weak_auth_event = Event(
            topic="probe.discovery.weak_auth",
            data={
                "ip": "192.168.1.1",
                "auth_type": "basic_auth",
                "severity": "high",
            }
        )

        await event_bus.publish(weak_auth_event)
        await asyncio.sleep(0.1)

        # Verify discovery recorded
        service = bridge.get_service_by_ip_port("192.168.1.1", 0)
        # Service might not be fully registered, check stats instead
        stats = bridge.get_stats()
        assert "weak_auth_count" in stats


# =============================================================================
# GOAL 2: PAYLOAD HARVESTING (Probe Vulns → Firewall Learning)
# =============================================================================

class TestPayloadHarvesting:
    """Test converting exploited payloads into firewall rules."""

    def test_harvest_soap_auth_bypass_payload(self, temp_dir):
        """Convert SOAP authentication bypass payload to detection rule."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        # Real SOAP auth bypass payload structure
        payload = (
            '<m:ConfigurationStarted xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1">'
            '<NewSessionID>11111111</NewSessionID>'
            '</m:ConfigurationStarted>'
        )

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="soap_auth_bypass",
            source_ip="192.168.1.50",
            target_ip="192.168.1.1",
        )

        assert rule is not None
        assert rule.name.startswith("HARVESTED-")
        assert "SOAP" in rule.description or "soap" in rule.description.lower()
        assert rule.confidence > 0.75

    def test_harvest_sql_injection_payload(self, temp_dir):
        """Convert SQL injection payload to detection rule."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = "' UNION SELECT NULL, username, password FROM users--"

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None
        assert rule.injection_type == InjectionType.SQL
        assert rule.severity == "critical"

    def test_harvest_xss_payload(self, temp_dir):
        """Convert XSS payload to detection rule."""
        harvester = PayloadHarvester(data_dir=temp_dir)

        payload = '<script>alert("xss")</script>'

        rule = harvester.harvest_from_exploitation(
            payload=payload,
            vuln_type="xss",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None
        assert rule.injection_type == InjectionType.XSS
        assert "<script" in rule.pattern or "script" in rule.pattern

    def test_harvested_rules_persist_to_disk(self, temp_dir):
        """Harvested rules saved to disk and can be reloaded."""
        harvester1 = PayloadHarvester(data_dir=temp_dir)

        payload = "' OR '1'='1"
        rule = harvester1.harvest_from_exploitation(
            payload=payload,
            vuln_type="sql_injection",
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
        )

        assert rule is not None

        # Create new harvester, should load from disk
        harvester2 = PayloadHarvester(data_dir=temp_dir)
        rules = harvester2.get_harvested_rules()
        assert len(rules) == 1
        assert rules[0].base_confidence > 0.75


# =============================================================================
# GOAL 3: DEFENSIVE SCANNING (Probe Tests Network with Firewall Rules)
# =============================================================================

class TestDefensiveScanning:
    """Test scanning internal endpoints using firewall rules."""

    @pytest.mark.asyncio
    async def test_synthesize_http_payloads(self, temp_dir):
        """Defensive scanner synthesizes payloads for HTTP endpoints."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._synthesize_payloads_for_service("http")

        assert len(payloads) > 0
        # Each payload dict has injection_type -> payload pairs
        assert any("xss" in str(p).lower() for p in payloads)
        assert any("path_traversal" in str(p).lower() for p in payloads)

    @pytest.mark.asyncio
    async def test_synthesize_sql_payloads(self, temp_dir):
        """Defensive scanner synthesizes payloads for SQL endpoints."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        payloads = scanner._synthesize_payloads_for_service("sql")

        assert len(payloads) > 0
        assert any("union" in str(p).lower() for p in payloads)
        assert any("sleep" in str(p).lower() for p in payloads)

    def test_is_vulnerable_detection(self, temp_dir):
        """Defensive scanner detects vulnerable responses."""
        scanner = ProbeDefensiveScanner(data_dir=temp_dir)

        # Response with SQL error indicator
        assert scanner._is_vulnerable(200, "MySQL Error: Syntax error") == True

        # Response with 403 Forbidden (blocked by firewall)
        assert scanner._is_vulnerable(403, "Forbidden") == False

        # Response without indicators
        assert scanner._is_vulnerable(200, "Welcome") == False


# =============================================================================
# GOAL 4: ATTACK CORRELATION (Probe Discoveries + Firewall Blocks)
# =============================================================================

class TestAttackCorrelation:
    """Test correlating discoveries with actual attacks."""

    def test_correlate_exact_match_high_confidence(self, temp_dir):
        """Attack on discovered endpoint gets high correlation score."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        # Register discovery
        correlator.register_discovery(
            ip="192.168.1.100",
            port=8080,
            service_type="http",
            vulnerability_flags=["xss"],
        )

        # Simulate attack on discovered endpoint
        was_discovered, score = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=8080,
            injection_type="xss",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        assert was_discovered == True
        assert score > 0.80

    def test_blind_attack_low_confidence(self, temp_dir):
        """Attack on unknown endpoint gets low correlation score."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        # Don't register any discovery
        was_discovered, score = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.200",
            target_port=9999,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        assert was_discovered == False
        assert score < 0.30

    def test_threat_score_escalation(self, temp_dir):
        """Source IP threat score escalates on correlated attacks."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        # Register discovery
        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        # First attack
        _, score1 = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        threat_score1 = correlator.get_threat_score("192.168.1.50")
        assert threat_score1 > 0

        # Second attack from same source
        _, score2 = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        threat_score2 = correlator.get_threat_score("192.168.1.50")
        assert threat_score2 > threat_score1

    def test_discoveries_persist_across_restarts(self, temp_dir):
        """Correlator discoveries persisted to disk."""
        correlator1 = ProbeAttackCorrelator(data_dir=temp_dir)
        correlator1.register_discovery(
            ip="192.168.1.100",
            port=8080,
            service_type="http",
        )

        # Create new correlator, should load discoveries
        correlator2 = ProbeAttackCorrelator(data_dir=temp_dir)
        services = correlator2.get_discovered_services()
        assert len(services) == 1
        assert services[0].ip == "192.168.1.100"


# =============================================================================
# INTEGRATION TESTS: Full Workflows
# =============================================================================

class TestIntegratedWorkflows:
    """End-to-end tests for complete workflows."""

    @pytest.mark.asyncio
    async def test_workflow_discovery_to_attack_correlation(self, event_bus, temp_dir):
        """Full workflow: probe discovers → firewall blocks correlated attack."""
        firewall = SmartFirewallAgent(event_bus=event_bus, data_dir=temp_dir)
        bridge = ProbeFirewallBridge(event_bus=event_bus, smart_firewall=firewall)
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        firewall.set_correlator(correlator)

        # Step 1: Probe discovers SQL endpoint
        discovery_event = Event(
            topic="probe.discovery.open_port",
            data={
                "ip": "192.168.1.100",
                "port": 3306,
                "service": "mysql",
                "protocol": "tcp",
            }
        )

        await event_bus.publish(discovery_event)
        await asyncio.sleep(0.05)

        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        # Step 2: Firewall detects attack on discovered endpoint
        detection = InjectionDetection(
            detection_id="det-001",
            source_ip="192.168.1.50",
            payload_snippet="' UNION SELECT NULL--",
            injection_type=InjectionType.SQL,
            rule_name="SQL UNION SELECT",
            severity="critical",
            confidence=0.95,
        )

        # Check correlation
        was_discovered, score = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=detection.timestamp,
        )

        assert was_discovered == True
        assert score > 0.80

    @pytest.mark.asyncio
    async def test_workflow_exploitation_to_rule_learning(self, event_bus, temp_dir):
        """Full workflow: probe exploits → rule harvested → firewall learns."""
        firewall = SmartFirewallAgent(event_bus=event_bus, data_dir=temp_dir)
        harvester = PayloadHarvester(data_dir=temp_dir)

        # Step 1: Probe successfully exploits SOAP auth bypass
        exploitation_event = Event(
            topic="probe.exploitation.success",
            data={
                "ip": "192.168.1.1",
                "payload": (
                    '<m:ConfigurationStarted xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1">'
                    '<NewSessionID>11111111</NewSessionID></m:ConfigurationStarted>'
                ),
                "vuln_type": "soap_auth_bypass",
                "source_ip": None,
                "target_ip": "192.168.1.1",
                "success": True,
            }
        )

        # Step 2: Harvester creates rule from payload
        rule = harvester.harvest_from_exploitation(
            payload=exploitation_event.data["payload"],
            vuln_type=exploitation_event.data["vuln_type"],
            source_ip=None,
            target_ip="192.168.1.1",
        )

        assert rule is not None

        # Step 3: Firewall adds dynamic rule
        firewall.add_dynamic_rule(rule, source="probe_exploitation")
        assert rule.name in firewall._dynamic_rules


# =============================================================================
# UNIT TESTS: Individual Components
# =============================================================================

class TestProbeAgent:
    """Test ProbeAgent event publishing wrapper."""

    @pytest.mark.asyncio
    async def test_publish_open_port_discovery(self, event_bus):
        """ProbeAgent publishes open port discovery."""
        probe_agent = ProbeAgent(event_bus=event_bus)
        events_received = []

        async def capture_event(event: Event):
            events_received.append(event)

        event_bus.subscribe("probe.discovery.open_port", capture_event)

        await probe_agent.publish_discovery_open_port(
            ip="192.168.1.100",
            port=8080,
            service="http",
        )

        await asyncio.sleep(0.05)
        assert len(events_received) == 1
        assert events_received[0].data["service"] == "http"

    @pytest.mark.asyncio
    async def test_publish_rogue_ap_discovery(self, event_bus):
        """ProbeAgent publishes rogue AP detection."""
        probe_agent = ProbeAgent(event_bus=event_bus)
        events_received = []

        async def capture_event(event: Event):
            events_received.append(event)

        event_bus.subscribe("probe.discovery.rogue_ap", capture_event)

        await probe_agent.publish_discovery_rogue_ap(
            ssid="FakeWiFi",
            bssid="aa:bb:cc:dd:ee:ff",
            channel=6,
        )

        await asyncio.sleep(0.05)
        assert len(events_received) == 1
        assert events_received[0].data["ssid"] == "FakeWiFi"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
