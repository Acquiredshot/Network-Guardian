# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Probe ↔ Firewall Intelligence Bridge

Orchestrates bidirectional intelligence sharing between the network probe
(discovery, reconnaissance, exploitation) and the smart firewall agent
(injection detection, blocking, rule adaptation).

Key flows:
  1. Probe discovers service → Bridge adapts firewall rules for that service
  2. Probe exploits vulnerability → Bridge feeds payload to rule harvester
  3. Probe identifies weak auth → Bridge increases firewall sensitivity
  4. Firewall detects attack on discovered endpoint → Escalate threat score
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING, Optional

from network_guardian.core.events import Event

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus
    from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent

logger = logging.getLogger("network_guardian.agent.probe_firewall_bridge")


@dataclass
class DiscoveredService:
    """Record of a service discovered by probe."""
    ip: str
    port: int
    service_type: str  # "http", "https", "smtp", "ftp", "sql", "soap", "ssh", etc.
    protocol: str  # "tcp" | "udp"
    version: Optional[str] = None
    credentials_weak: bool = False
    auth_method: Optional[str] = None
    vulnerability_indicators: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ServiceProfile:
    """Firewall's profile of how to handle a service type."""
    service_type: str
    enabled_rules: set[str] = field(default_factory=set)
    confidence_multiplier: float = 1.0
    rate_limit_threshold: Optional[int] = None
    enhanced_logging: bool = False
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProbeFirewallBridge:
    """
    Orchestrates intelligence flow between probe and firewall.

    Subscribes to probe discovery/exploitation events and adapts firewall
    behavior accordingly. Maintains service profiles and tracks what the
    probe has discovered.
    """

    def __init__(
        self,
        event_bus: EventBus,
        smart_firewall: Optional["SmartFirewallAgent"] = None,
        data_dir: Optional[Path] = None,
    ):
        self._event_bus = event_bus
        self._firewall = smart_firewall
        self._data_dir = data_dir or Path.home() / ".network_guardian" / "probe_firewall_bridge"
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._discovered_services: dict[str, DiscoveredService] = {}
        self._service_profiles: dict[str, ServiceProfile] = {}
        self._rule_mappings: dict[str, list[str]] = {}

        self._load_service_profiles()
        self._load_discoveries()
        self._register_handlers()

    def set_smart_firewall(self, smart_firewall: "SmartFirewallAgent") -> None:
        """Wire smart firewall reference (used to break circular dependencies)."""
        self._firewall = smart_firewall

    def _register_handlers(self) -> None:
        """Subscribe to probe events."""
        self._event_bus.subscribe("probe.discovery.open_port", self._on_open_port)
        self._event_bus.subscribe("probe.discovery.weak_auth", self._on_weak_auth)
        self._event_bus.subscribe("probe.discovery.rogue_ap", self._on_rogue_ap)
        self._event_bus.subscribe("probe.exploitation.success", self._on_exploitation_success)
        self._event_bus.subscribe("probe.exploitation.failure", self._on_exploitation_failure)

    async def _on_open_port(self, event: Event) -> None:
        """Handle probe discovery of open port."""
        data = event.data
        ip = data.get("ip")
        port = data.get("port")
        service = data.get("service", "unknown")

        if not ip or port is None:
            return

        key = f"{ip}:{port}"
        self._discovered_services[key] = DiscoveredService(
            ip=ip,
            port=port,
            service_type=service,
            protocol=data.get("protocol", "tcp"),
            version=data.get("version"),
        )

        logger.info(f"Registered service: {service} on {key}")
        await self.adapt_rules_for_service(service)
        self._persist_discoveries()

    async def _on_weak_auth(self, event: Event) -> None:
        """Handle probe discovery of weak authentication."""
        data = event.data
        ip = data.get("ip")
        auth_type = data.get("auth_type")
        severity = data.get("severity", "medium")

        logger.warning(
            f"Weak auth detected: {auth_type} on {ip} (severity: {severity})"
        )

        for key in list(self._discovered_services.keys()):
            if self._discovered_services[key].ip == ip:
                self._discovered_services[key].credentials_weak = True
                self._discovered_services[key].auth_method = auth_type

        if self._firewall:
            await self._firewall.record_request(ip)

        self._persist_discoveries()

    async def _on_rogue_ap(self, event: Event) -> None:
        """Handle probe detection of rogue AP / evil twin."""
        data = event.data
        ssid = data.get("ssid")
        bssid = data.get("bssid")
        severity = data.get("severity", "critical")

        logger.critical(f"Rogue AP detected: {ssid} ({bssid}) - severity: {severity}")

        if self._firewall:
            await self._event_bus.publish(Event(
                topic="firewall.threat.rogue_ap",
                data={"ssid": ssid, "bssid": bssid, "severity": severity}
            ))

    async def _on_exploitation_success(self, event: Event) -> None:
        """Handle successful exploitation by probe."""
        data = event.data
        ip = data.get("ip")
        payload = data.get("payload", "")
        vuln_type = data.get("vuln_type", "unknown")

        logger.warning(
            f"Exploitation success: {vuln_type} on {ip}, payload len={len(payload)}"
        )

        if self._firewall:
            await self._event_bus.publish(Event(
                topic="bridge.payload_learned",
                data={
                    "payload": payload[:500],
                    "vuln_type": vuln_type,
                    "source_ip": ip,
                    "success": True,
                }
            ))

    async def _on_exploitation_failure(self, event: Event) -> None:
        """Handle failed exploitation attempt."""
        data = event.data
        vuln_type = data.get("vuln_type", "unknown")
        reason = data.get("reason", "unknown")

        logger.debug(f"Exploitation failed: {vuln_type}, reason: {reason}")

    async def adapt_rules_for_service(self, service_type: str) -> None:
        """
        Adapt firewall rules based on discovered service type.

        Enable service-specific detection rules and adjust thresholds.
        """
        if not self._firewall:
            return

        if service_type not in self._service_profiles:
            self._service_profiles[service_type] = ServiceProfile(service_type=service_type)

        profile = self._service_profiles[service_type]

        service_rule_map = {
            "http": ["XSS Script Tag", "XSS Event Handler", "Path Traversal Sequence"],
            "https": ["XSS Script Tag", "XSS Event Handler", "Path Traversal Sequence"],
            "sql": ["SQL UNION SELECT", "SQL Tautology", "SQL Stacked Query"],
            "mysql": ["SQL UNION SELECT", "SQL Tautology", "SQL Error-based"],
            "postgres": ["SQL UNION SELECT", "SQL Tautology", "SQL Error-based"],
            "ftp": ["CMD Pipe/Semicolon", "CMD Redirection"],
            "smtp": ["Header Newline Split", "CRLF Header Injection"],
            "ldap": ["LDAP Filter Escape", "LDAP AND/OR Bypass"],
            "soap": ["XXE ENTITY Declaration", "XXE Parameter Entity"],
            "graphql": ["GraphQL Introspection Probe", "GraphQL Batch Attack"],
            "mongodb": ["NoSQL MongoDB Operator", "NoSQL JavaScript Injection"],
            "redis": ["CMD Pipe/Semicolon", "NoSQL Array Operator Bypass"],
        }

        if service_type in service_rule_map:
            profile.enabled_rules = set(service_rule_map[service_type])
            logger.info(f"Enabled {len(profile.enabled_rules)} rules for {service_type}")

        profile.enhanced_logging = True
        profile.last_updated = datetime.now(timezone.utc).isoformat()

        self._service_profiles[service_type] = profile

    def register_discovered_service(
        self,
        ip: str,
        port: int,
        service_type: str,
        protocol: str = "tcp",
        version: Optional[str] = None,
    ) -> None:
        """Register a discovered service."""
        key = f"{ip}:{port}"
        self._discovered_services[key] = DiscoveredService(
            ip=ip,
            port=port,
            service_type=service_type,
            protocol=protocol,
            version=version,
        )
        self._persist_discoveries()

    def get_discovered_services(self) -> list[DiscoveredService]:
        """Get all discovered services."""
        return list(self._discovered_services.values())

    def get_service_by_ip_port(self, ip: str, port: int) -> Optional[DiscoveredService]:
        """Look up service by IP and port."""
        key = f"{ip}:{port}"
        return self._discovered_services.get(key)

    def _load_service_profiles(self) -> None:
        """Load service profiles from disk."""
        profiles_file = self._data_dir / "service_profiles.json"
        if not profiles_file.exists():
            return

        try:
            data = json.loads(profiles_file.read_text())
            for service_type, profile_data in data.items():
                self._service_profiles[service_type] = ServiceProfile(
                    service_type=service_type,
                    enabled_rules=set(profile_data.get("enabled_rules", [])),
                    confidence_multiplier=profile_data.get("confidence_multiplier", 1.0),
                    rate_limit_threshold=profile_data.get("rate_limit_threshold"),
                    enhanced_logging=profile_data.get("enhanced_logging", False),
                )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load service profiles: {e}")

    def _load_discoveries(self) -> None:
        """Load discovered services from disk."""
        discoveries_file = self._data_dir / "discoveries.json"
        if not discoveries_file.exists():
            return

        try:
            data = json.loads(discoveries_file.read_text())
            for key, service_data in data.items():
                self._discovered_services[key] = DiscoveredService(**service_data)
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.warning(f"Failed to load discoveries: {e}")

    def _persist_discoveries(self) -> None:
        """Save discovered services to disk."""
        discoveries_file = self._data_dir / "discoveries.json"
        try:
            data = {
                key: asdict(service)
                for key, service in self._discovered_services.items()
            }
            discoveries_file.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.error(f"Failed to persist discoveries: {e}")

    def get_stats(self) -> dict[str, Any]:
        """Get bridge statistics."""
        return {
            "total_discovered_services": len(self._discovered_services),
            "weak_auth_count": sum(
                1 for s in self._discovered_services.values() if s.credentials_weak
            ),
            "service_types": list(set(s.service_type for s in self._discovered_services.values())),
            "active_profiles": len(self._service_profiles),
        }
