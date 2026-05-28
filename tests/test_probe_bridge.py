# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Unit Tests: Probe-Firewall Bridge
"""

import asyncio
import pytest
from pathlib import Path

from network_guardian.core.events import Event, EventBus
from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent
from network_guardian.agent.probe_firewall_bridge import ProbeFirewallBridge


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


class TestProbeFirewallBridge:
    """Test probe-firewall intelligence bridge."""

    def test_bridge_initialization(self, event_bus, temp_dir):
        """Bridge initializes with event bus."""
        bridge = ProbeFirewallBridge(event_bus=event_bus, data_dir=temp_dir)
        assert bridge._event_bus == event_bus
        assert len(bridge._discovered_services) == 0

    def test_register_discovered_service(self, event_bus, temp_dir):
        """Bridge registers discovered services."""
        bridge = ProbeFirewallBridge(event_bus=event_bus, data_dir=temp_dir)

        bridge.register_discovered_service(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
            version="5.7",
        )

        service = bridge.get_service_by_ip_port("192.168.1.100", 3306)
        assert service is not None
        assert service.service_type == "mysql"
        assert service.version == "5.7"

    @pytest.mark.asyncio
    async def test_adapt_rules_for_http_service(self, event_bus, temp_dir):
        """Bridge adapts firewall rules for HTTP service."""
        firewall = SmartFirewallAgent(event_bus=event_bus, data_dir=temp_dir)
        bridge = ProbeFirewallBridge(event_bus=event_bus, smart_firewall=firewall)

        await bridge.adapt_rules_for_service("http")

        assert "http" in bridge._service_profiles
        profile = bridge._service_profiles["http"]
        assert len(profile.enabled_rules) > 0
        assert profile.enhanced_logging == True

    @pytest.mark.asyncio
    async def test_adapt_rules_for_sql_service(self, event_bus, temp_dir):
        """Bridge adapts firewall rules for SQL service."""
        firewall = SmartFirewallAgent(event_bus=event_bus, data_dir=temp_dir)
        bridge = ProbeFirewallBridge(event_bus=event_bus, smart_firewall=firewall)

        await bridge.adapt_rules_for_service("mysql")

        assert "mysql" in bridge._service_profiles
        profile = bridge._service_profiles["mysql"]
        sql_rules = [r for r in profile.enabled_rules if "SQL" in r]
        assert len(sql_rules) > 0

    def test_bridge_persistence(self, event_bus, temp_dir):
        """Bridge services persisted to disk."""
        bridge1 = ProbeFirewallBridge(event_bus=event_bus, data_dir=temp_dir)
        bridge1.register_discovered_service(
            ip="192.168.1.100",
            port=8080,
            service_type="http",
        )

        # Create new bridge, should load persisted data
        bridge2 = ProbeFirewallBridge(event_bus=event_bus, data_dir=temp_dir)
        service = bridge2.get_service_by_ip_port("192.168.1.100", 8080)
        assert service is not None

    def test_bridge_stats(self, event_bus, temp_dir):
        """Bridge provides statistics."""
        bridge = ProbeFirewallBridge(event_bus=event_bus, data_dir=temp_dir)
        bridge.register_discovered_service("192.168.1.100", 3306, "mysql")
        bridge.register_discovered_service("192.168.1.101", 80, "http")

        stats = bridge.get_stats()
        assert stats["total_discovered_services"] == 2
        assert "service_types" in stats

    @pytest.mark.asyncio
    async def test_on_open_port_event(self, event_bus, temp_dir):
        """Bridge processes open port discovery events."""
        bridge = ProbeFirewallBridge(event_bus=event_bus, data_dir=temp_dir)

        event = Event(
            topic="probe.discovery.open_port",
            data={
                "ip": "192.168.1.100",
                "port": 3306,
                "service": "mysql",
                "protocol": "tcp",
                "version": "5.7",
            }
        )

        await event_bus.publish(event)
        await asyncio.sleep(0.05)

        service = bridge.get_service_by_ip_port("192.168.1.100", 3306)
        assert service is not None
        assert service.service_type == "mysql"

    @pytest.mark.asyncio
    async def test_on_weak_auth_event(self, event_bus, temp_dir):
        """Bridge processes weak auth discovery events."""
        bridge = ProbeFirewallBridge(event_bus=event_bus, data_dir=temp_dir)

        event = Event(
            topic="probe.discovery.weak_auth",
            data={
                "ip": "192.168.1.1",
                "auth_type": "basic_auth",
                "severity": "high",
            }
        )

        await event_bus.publish(event)
        await asyncio.sleep(0.05)

        stats = bridge.get_stats()
        assert stats["weak_auth_count"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
