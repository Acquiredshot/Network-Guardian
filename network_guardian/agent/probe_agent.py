# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Probe Agent — Event Publishing Wrapper

Wraps the standalone probe functions with event publishing to integrate
discoveries and exploitations with the smart firewall system.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from network_guardian.core.events import Event

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.probe_agent")


class ProbeAgent:
    """
    Wraps probe functionality with event publishing.

    Publishes probe discoveries and exploitations to the event bus
    so the smart firewall can adapt and learn from reconnaissance.
    """

    def __init__(self, event_bus: "EventBus | None" = None):
        self._event_bus = event_bus

    async def publish_discovery_open_port(
        self,
        ip: str,
        port: int,
        service: str,
        protocol: str = "tcp",
        version: str | None = None,
    ) -> None:
        """Publish discovery of an open port/service."""
        if not self._event_bus:
            return

        try:
            await self._event_bus.publish(Event(
                topic="probe.discovery.open_port",
                data={
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "protocol": protocol,
                    "version": version,
                }
            ))
            logger.debug(f"Published open port discovery: {service} on {ip}:{port}")
        except Exception as e:
            logger.warning(f"Failed to publish port discovery: {e}")

    async def publish_discovery_weak_auth(
        self,
        ip: str,
        auth_type: str,
        severity: str = "medium",
    ) -> None:
        """Publish discovery of weak authentication."""
        if not self._event_bus:
            return

        try:
            await self._event_bus.publish(Event(
                topic="probe.discovery.weak_auth",
                data={
                    "ip": ip,
                    "auth_type": auth_type,
                    "severity": severity,
                }
            ))
            logger.debug(f"Published weak auth discovery: {auth_type} on {ip}")
        except Exception as e:
            logger.warning(f"Failed to publish weak auth discovery: {e}")

    async def publish_discovery_rogue_ap(
        self,
        ssid: str,
        bssid: str,
        channel: int | None = None,
        severity: str = "critical",
    ) -> None:
        """Publish discovery of rogue AP / evil twin."""
        if not self._event_bus:
            return

        try:
            await self._event_bus.publish(Event(
                topic="probe.discovery.rogue_ap",
                data={
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": channel,
                    "severity": severity,
                }
            ))
            logger.warning(f"Published rogue AP discovery: {ssid} ({bssid})")
        except Exception as e:
            logger.warning(f"Failed to publish rogue AP discovery: {e}")

    async def publish_exploitation_success(
        self,
        ip: str,
        payload: str,
        vuln_type: str,
        target_ip: str | None = None,
    ) -> None:
        """Publish successful exploitation by probe."""
        if not self._event_bus:
            return

        try:
            await self._event_bus.publish(Event(
                topic="probe.exploitation.success",
                data={
                    "ip": ip,
                    "payload": payload,
                    "vuln_type": vuln_type,
                    "source_ip": ip,
                    "target_ip": target_ip or ip,
                    "success": True,
                }
            ))
            logger.warning(f"Published exploitation success: {vuln_type} on {ip}")
        except Exception as e:
            logger.warning(f"Failed to publish exploitation success: {e}")

    async def publish_exploitation_failure(
        self,
        ip: str,
        payload: str,
        vuln_type: str,
        reason: str,
    ) -> None:
        """Publish failed exploitation attempt."""
        if not self._event_bus:
            return

        try:
            await self._event_bus.publish(Event(
                topic="probe.exploitation.failure",
                data={
                    "ip": ip,
                    "payload": payload,
                    "vuln_type": vuln_type,
                    "reason": reason,
                    "success": False,
                }
            ))
            logger.debug(f"Published exploitation failure: {vuln_type} on {ip}, reason: {reason}")
        except Exception as e:
            logger.warning(f"Failed to publish exploitation failure: {e}")

    async def publish_scan_complete(
        self,
        agent_id: str,
        discoveries: int,
    ) -> None:
        """Publish completion of probe scan cycle."""
        if not self._event_bus:
            return

        try:
            await self._event_bus.publish(Event(
                topic="probe.lifecycle.scan_complete",
                data={
                    "agent_id": agent_id,
                    "discoveries": discoveries,
                }
            ))
            logger.info(f"Published scan complete: {discoveries} discoveries")
        except Exception as e:
            logger.warning(f"Failed to publish scan complete: {e}")

    def set_event_bus(self, event_bus: "EventBus") -> None:
        """Set the event bus for publishing."""
        self._event_bus = event_bus
