# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Probe Attack Correlator — Connecting Discoveries to Actual Attacks

Maintains a cache of discovered hosts, ports, and services. When the firewall
detects an injection attack, the correlator checks if the target matches a
discovered endpoint. This correlation increases confidence that an attacker
performed active reconnaissance before exploiting.

Correlation indicators:
  - Target IP/port matches discovered service → HIGH confidence attack
  - Target IP known but port different → MEDIUM confidence (lateral movement)
  - Target IP unknown → LOW confidence (blind attack or new endpoint)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from network_guardian.agent.smart_firewall_agent import InjectionDetection

logger = logging.getLogger("network_guardian.agent.probe_attack_correlator")


@dataclass
class DiscoveryRecord:
    """Record of probe discovering a host/service."""
    ip: str
    port: int
    service_type: str
    discovery_time: str
    vulnerability_flags: list[str] = field(default_factory=list)


@dataclass
class CorrelationEvent:
    """Record of a correlated attack."""
    source_ip: str
    target_ip: str
    target_port: int
    injection_type: str
    discovery_time: str
    attack_time: str
    time_delta_seconds: int
    correlation_score: float
    was_discovered_first: bool


class ProbeAttackCorrelator:
    """
    Correlates probe discoveries with actual firewall-detected attacks.

    Maintains persistent cache of discovered endpoints and matches against
    detected injections to identify sophisticated attack patterns.
    """

    def __init__(self, data_dir: Path | None = None):
        self._data_dir = data_dir or Path.home() / ".network_guardian" / "attack_correlator"
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._discoveries: dict[str, DiscoveryRecord] = {}
        self._correlations: dict[str, CorrelationEvent] = {}
        self._source_ip_scores: dict[str, float] = {}

        self._load_discoveries()
        self._load_correlations()

    def register_discovery(
        self,
        ip: str,
        port: int,
        service_type: str,
        vulnerability_flags: list[str] | None = None,
    ) -> None:
        """
        Register a discovered host/service.

        Args:
            ip: Target IP address
            port: Target port
            service_type: Type of service (http, sql, soap, etc.)
            vulnerability_flags: List of identified vulnerabilities
        """
        key = f"{ip}:{port}"

        self._discoveries[key] = DiscoveryRecord(
            ip=ip,
            port=port,
            service_type=service_type,
            discovery_time=datetime.now(timezone.utc).isoformat(),
            vulnerability_flags=vulnerability_flags or [],
        )

        logger.debug(f"Registered discovery: {key} ({service_type})")
        self._persist_discoveries()

    def correlate_attack(
        self,
        source_ip: str,
        target_ip: str,
        target_port: int,
        injection_type: str,
        detection_time: str,
    ) -> tuple[bool, float]:
        """
        Check if attack correlates with discovered endpoint.

        Returns:
            (was_correlated, correlation_score)
            correlation_score: 0.0 (blind attack) to 1.0 (perfect correlation)
        """
        correlation_score = 0.0
        was_discovered = False

        key = f"{target_ip}:{target_port}"
        discovery = self._discoveries.get(key)

        if discovery:
            was_discovered = True
            correlation_score = self._calculate_exact_match_score(
                discovery, source_ip, detection_time
            )
            logger.info(
                f"CORRELATED ATTACK: {source_ip} → {target_ip}:{target_port} "
                f"({injection_type}), score={correlation_score:.2f}"
            )
        else:
            correlation_score = self._calculate_blind_attack_score(
                source_ip, target_ip, target_port
            )
            logger.debug(
                f"Blind attack: {source_ip} → {target_ip}:{target_port}, score={correlation_score:.2f}"
            )

        if correlation_score > 0.0:
            self._record_correlation(
                source_ip, target_ip, target_port, injection_type,
                discovery, correlation_score, detection_time
            )

        self._update_source_ip_score(source_ip, correlation_score)

        return was_discovered, correlation_score

    def _calculate_exact_match_score(
        self,
        discovery: DiscoveryRecord,
        source_ip: str,
        detection_time: str,
    ) -> float:
        """
        Calculate score when attack targets discovered endpoint.

        Factors:
        - Time between discovery and attack (closer = higher)
        - Vulnerability flags on target (more = higher)
        - Prior attack history from same source (repeat = higher)
        """
        try:
            discovery_dt = datetime.fromisoformat(discovery.discovery_time)
            detection_dt = datetime.fromisoformat(detection_time)
            time_delta = (detection_dt - discovery_dt).total_seconds()
        except (ValueError, TypeError):
            time_delta = 0

        base_score = 0.85

        if time_delta >= 0 and time_delta <= 3600:
            base_score += 0.10

        if len(discovery.vulnerability_flags) > 0:
            base_score = min(base_score + 0.05 * len(discovery.vulnerability_flags), 1.0)

        if source_ip in self._source_ip_scores:
            if self._source_ip_scores[source_ip] > 0.5:
                base_score = min(base_score + 0.05, 1.0)

        return min(base_score, 1.0)

    def _calculate_blind_attack_score(
        self,
        source_ip: str,
        target_ip: str,
        target_port: int,
    ) -> float:
        """
        Calculate score for attack on non-discovered endpoint.

        Low score unless:
        - Same source IP has prior correlated attacks
        - Port suggests standard service (80, 443, 22, etc.)
        """
        score = 0.15

        if source_ip in self._source_ip_scores:
            if self._source_ip_scores[source_ip] > 0.7:
                score += 0.20

        standard_ports = {80, 443, 22, 25, 53, 110, 143, 3306, 5432, 27017}
        if target_port in standard_ports:
            score += 0.10

        return min(score, 1.0)

    def _record_correlation(
        self,
        source_ip: str,
        target_ip: str,
        target_port: int,
        injection_type: str,
        discovery: DiscoveryRecord | None,
        correlation_score: float,
        detection_time: str,
    ) -> None:
        """Record a correlated attack event."""
        try:
            if discovery:
                discovery_time = discovery.discovery_time
                discovery_dt = datetime.fromisoformat(discovery_time)
                detection_dt = datetime.fromisoformat(detection_time)
                time_delta = int((detection_dt - discovery_dt).total_seconds())
            else:
                discovery_time = "unknown"
                time_delta = -1
        except (ValueError, TypeError):
            discovery_time = "unknown"
            time_delta = -1

        event = CorrelationEvent(
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=target_port,
            injection_type=injection_type,
            discovery_time=discovery_time,
            attack_time=detection_time,
            time_delta_seconds=time_delta,
            correlation_score=correlation_score,
            was_discovered_first=discovery is not None,
        )

        key = f"{source_ip}_{target_ip}_{target_port}_{detection_time}"
        self._correlations[key] = event

        self._persist_correlations()

    def _update_source_ip_score(self, source_ip: str, correlation_score: float) -> None:
        """
        Update threat score for source IP based on correlation.

        Higher score = more likely to be attacker doing reconnaissance.
        """
        if source_ip not in self._source_ip_scores:
            self._source_ip_scores[source_ip] = 0.0

        self._source_ip_scores[source_ip] = min(
            self._source_ip_scores[source_ip] + correlation_score * 0.1,
            1.0
        )

    def get_threat_score(self, source_ip: str) -> float:
        """Get current threat score for source IP."""
        return self._source_ip_scores.get(source_ip, 0.0)

    def get_discovered_services(self) -> list[DiscoveryRecord]:
        """Get all discovered services."""
        return list(self._discoveries.values())

    def get_service_by_ip_port(self, ip: str, port: int) -> DiscoveryRecord | None:
        """Look up discovered service by IP and port."""
        key = f"{ip}:{port}"
        return self._discoveries.get(key)

    def get_correlations_for_source(self, source_ip: str) -> list[CorrelationEvent]:
        """Get all correlated attacks from a source IP."""
        return [c for c in self._correlations.values() if c.source_ip == source_ip]

    def get_correlations_for_target(self, target_ip: str) -> list[CorrelationEvent]:
        """Get all correlated attacks against a target IP."""
        return [c for c in self._correlations.values() if c.target_ip == target_ip]

    def _load_discoveries(self) -> None:
        """Load discovery cache from disk."""
        discoveries_file = self._data_dir / "discoveries.json"
        if not discoveries_file.exists():
            return

        try:
            data = json.loads(discoveries_file.read_text())
            for key, record_data in data.items():
                self._discoveries[key] = DiscoveryRecord(**record_data)
            logger.info(f"Loaded {len(self._discoveries)} cached discoveries")
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.warning(f"Failed to load discoveries: {e}")

    def _persist_discoveries(self) -> None:
        """Save discovery cache to disk."""
        discoveries_file = self._data_dir / "discoveries.json"
        try:
            data = {key: asdict(record) for key, record in self._discoveries.items()}
            discoveries_file.write_text(json.dumps(data, indent=2, default=str))
        except OSError as e:
            logger.error(f"Failed to persist discoveries: {e}")

    def _load_correlations(self) -> None:
        """Load correlation history from disk."""
        correlations_file = self._data_dir / "correlations.json"
        if not correlations_file.exists():
            return

        try:
            data = json.loads(correlations_file.read_text())
            for key, event_data in data.items():
                self._correlations[key] = CorrelationEvent(**event_data)
            logger.info(f"Loaded {len(self._correlations)} cached correlations")
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.warning(f"Failed to load correlations: {e}")

    def _persist_correlations(self) -> None:
        """Save correlation history to disk."""
        correlations_file = self._data_dir / "correlations.json"
        try:
            data = {key: asdict(event) for key, event in self._correlations.items()}
            correlations_file.write_text(json.dumps(data, indent=2, default=str))
        except OSError as e:
            logger.error(f"Failed to persist correlations: {e}")

    def get_stats(self) -> dict[str, Any]:
        """Get correlator statistics."""
        correlated_attacks = sum(1 for c in self._correlations.values() if c.was_discovered_first)
        blind_attacks = len(self._correlations) - correlated_attacks

        return {
            "total_discoveries": len(self._discoveries),
            "total_correlations": len(self._correlations),
            "correlated_attacks": correlated_attacks,
            "blind_attacks": blind_attacks,
            "tracked_source_ips": len(self._source_ip_scores),
            "avg_threat_score": (
                sum(self._source_ip_scores.values()) / max(len(self._source_ip_scores), 1)
            ),
        }
