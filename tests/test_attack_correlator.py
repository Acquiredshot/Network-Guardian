# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Unit Tests: Probe Attack Correlator
"""

import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from network_guardian.agent.probe_attack_correlator import ProbeAttackCorrelator


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


class TestProbeAttackCorrelator:
    """Test attack correlation engine."""

    def test_correlator_initialization(self, temp_dir):
        """Correlator initializes cleanly."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)
        assert correlator._data_dir == temp_dir
        assert len(correlator._discoveries) == 0

    def test_register_discovery(self, temp_dir):
        """Correlator registers discovered services."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        service = correlator.get_service_by_ip_port("192.168.1.100", 3306)
        assert service is not None
        assert service.service_type == "mysql"

    def test_exact_match_high_correlation(self, temp_dir):
        """Exact endpoint match yields high correlation score."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        # Register discovery
        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        # Attack on same endpoint
        was_discovered, score = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        assert was_discovered == True
        assert score > 0.80

    def test_blind_attack_low_correlation(self, temp_dir):
        """Attack on unknown endpoint yields low correlation score."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        # No discovery registered
        was_discovered, score = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.200",
            target_port=9999,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        assert was_discovered == False
        assert score < 0.30

    def test_correlation_with_vulnerability_flags(self, temp_dir):
        """Vulnerability flags increase correlation score."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        # Register discovery with vulnerability flags
        correlator.register_discovery(
            ip="192.168.1.100",
            port=8080,
            service_type="http",
            vulnerability_flags=["xss", "sql_injection"],
        )

        was_discovered, score1 = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=8080,
            injection_type="xss",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        # Register discovery without flags
        correlator2 = ProbeAttackCorrelator(data_dir=temp_dir)
        correlator2.register_discovery(
            ip="192.168.1.101",
            port=8081,
            service_type="http",
        )

        _, score2 = correlator2.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.101",
            target_port=8081,
            injection_type="xss",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        # Score with flags should be higher
        assert score1 > score2

    def test_threat_score_escalation(self, temp_dir):
        """Source IP threat score escalates on correlated attacks."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        initial_score = correlator.get_threat_score("192.168.1.50")
        assert initial_score == 0.0

        # First correlated attack
        _, _ = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        score1 = correlator.get_threat_score("192.168.1.50")
        assert score1 > 0.0

        # Second correlated attack
        _, _ = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        score2 = correlator.get_threat_score("192.168.1.50")
        assert score2 > score1

    def test_get_correlations_for_source(self, temp_dir):
        """Query correlations by source IP."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        # Multiple attacks from same source
        for i in range(3):
            correlator.correlate_attack(
                source_ip="192.168.1.50",
                target_ip="192.168.1.100",
                target_port=3306,
                injection_type="sql_injection",
                detection_time=datetime.now(timezone.utc).isoformat(),
            )

        correlations = correlator.get_correlations_for_source("192.168.1.50")
        assert len(correlations) == 3
        assert all(c.source_ip == "192.168.1.50" for c in correlations)

    def test_get_correlations_for_target(self, temp_dir):
        """Query correlations by target IP."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        # Multiple attacks against same target
        for i in range(3):
            correlator.correlate_attack(
                source_ip=f"192.168.1.{50+i}",
                target_ip="192.168.1.100",
                target_port=3306,
                injection_type="sql_injection",
                detection_time=datetime.now(timezone.utc).isoformat(),
            )

        correlations = correlator.get_correlations_for_target("192.168.1.100")
        assert len(correlations) == 3
        assert all(c.target_ip == "192.168.1.100" for c in correlations)

    def test_discoveries_persist_to_disk(self, temp_dir):
        """Discoveries persisted and reloaded."""
        correlator1 = ProbeAttackCorrelator(data_dir=temp_dir)

        correlator1.register_discovery(
            ip="192.168.1.100",
            port=8080,
            service_type="http",
        )

        # New correlator should load from disk
        correlator2 = ProbeAttackCorrelator(data_dir=temp_dir)
        service = correlator2.get_service_by_ip_port("192.168.1.100", 8080)
        assert service is not None
        assert service.service_type == "http"

    def test_time_delta_calculation(self, temp_dir):
        """Correlation events track time delta between discovery and attack."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        discovery_time = datetime.now(timezone.utc)
        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        # Attack 5 minutes later
        attack_time = (discovery_time + timedelta(minutes=5)).isoformat()

        was_discovered, score = correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=attack_time,
        )

        correlations = correlator.get_correlations_for_source("192.168.1.50")
        assert len(correlations) > 0
        # Time delta should be approximately 300 seconds
        assert 250 < correlations[0].time_delta_seconds < 350

    def test_correlator_stats(self, temp_dir):
        """Correlator provides statistics."""
        correlator = ProbeAttackCorrelator(data_dir=temp_dir)

        correlator.register_discovery(
            ip="192.168.1.100",
            port=3306,
            service_type="mysql",
        )

        # Correlated attack
        correlator.correlate_attack(
            source_ip="192.168.1.50",
            target_ip="192.168.1.100",
            target_port=3306,
            injection_type="sql_injection",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        # Blind attack
        correlator.correlate_attack(
            source_ip="192.168.1.51",
            target_ip="192.168.1.200",
            target_port=9999,
            injection_type="xss",
            detection_time=datetime.now(timezone.utc).isoformat(),
        )

        stats = correlator.get_stats()
        assert stats["total_discoveries"] == 1
        assert stats["total_correlations"] == 2
        assert stats["correlated_attacks"] == 1
        assert stats["blind_attacks"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
