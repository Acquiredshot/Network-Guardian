# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Audit Analyzer — ML-powered audit analysis.

Uses trained models to score hosts, identify vulnerability patterns,
prioritise findings, and detect performance bottlenecks from raw scan data.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

from network_guardian.ai.anomaly import AnomalyDetector, EnsembleDetector, IsolationForest, OneClassSVM
from network_guardian.models.network import Finding, Host, HostStatus, Severity

logger = logging.getLogger("network_guardian.ai.audit_analyzer")

# Shared literal constants
_CLEARTEXT_CREDENTIALS = "Cleartext credentials"

# ---------------------------------------------------------------------------
# Known-risk knowledge base
# ---------------------------------------------------------------------------

# Maps port → (service_name, base_risk_score, known_issues)
_PORT_RISK_DB: dict[int, tuple[str, float, list[str]]] = {
    21: ("FTP", 0.7, [_CLEARTEXT_CREDENTIALS, "Anonymous access possible"]),
    22: ("SSH", 0.2, ["Brute-force target"]),
    23: ("Telnet", 0.9, ["Cleartext protocol", "No encryption"]),
    25: ("SMTP", 0.4, ["Open relay risk", "Spam vector"]),
    53: ("DNS", 0.3, ["DNS amplification", "Zone transfer"]),
    80: ("HTTP", 0.3, ["Unencrypted traffic"]),
    110: ("POP3", 0.6, [_CLEARTEXT_CREDENTIALS]),
    111: ("RPCbind", 0.7, ["Information leakage", "Remote exploitation"]),
    135: ("MSRPC", 0.6, ["Windows remote exploitation"]),
    139: ("NetBIOS", 0.7, ["SMB relay", "Information leakage"]),
    143: ("IMAP", 0.5, [_CLEARTEXT_CREDENTIALS]),
    443: ("HTTPS", 0.1, ["Certificate issues"]),
    445: ("SMB", 0.8, ["EternalBlue", "Ransomware vector", "Lateral movement"]),
    993: ("IMAPS", 0.1, []),
    995: ("POP3S", 0.1, []),
    1433: ("MSSQL", 0.6, ["SQL injection target", "Brute-force"]),
    1521: ("Oracle", 0.6, ["TNS poisoning"]),
    3306: ("MySQL", 0.5, ["Brute-force", "Data exfiltration"]),
    3389: ("RDP", 0.7, ["BlueKeep", "Brute-force", "Credential stuffing"]),
    5432: ("PostgreSQL", 0.4, ["Brute-force"]),
    5900: ("VNC", 0.8, ["Weak auth", "No encryption"]),
    6379: ("Redis", 0.8, ["No auth by default", "Data theft"]),
    8080: ("HTTP-alt", 0.4, ["Admin panels", "Unencrypted"]),
    8443: ("HTTPS-alt", 0.2, []),
    27017: ("MongoDB", 0.8, ["No auth by default", "Data exfiltration"]),
}

# Port ranges that suggest excessive exposure
_EXCESSIVE_PORT_THRESHOLD = 20


@dataclass
class HostRiskProfile:
    """Aggregated risk profile for a single host."""

    host_ip: str
    risk_score: float  # 0.0-1.0
    open_port_count: int
    high_risk_services: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    anomaly_score: float = 0.0


class NetworkAuditAnalyzer:
    """Analyses scan results using ML models and a risk knowledge base.

    Workflow:
    1. Score each host's open ports against the risk DB
    2. Build feature vectors (port count, risk-service count, etc.)
    3. Run anomaly detectors to flag hosts that deviate from the fleet
    4. Generate prioritised findings
    """

    def __init__(self, detector: AnomalyDetector | None = None) -> None:
        if detector is None:
            ensemble = EnsembleDetector()
            ensemble.add_detector(IsolationForest(n_trees=50, max_samples=128, seed=42))
            ensemble.add_detector(OneClassSVM(nu=0.1, seed=42))
            detector = ensemble
        self._detector = detector
        self._baseline_fitted = False

    # -- Public API -----------------------------------------------------

    def analyse(self, hosts: list[Host]) -> list[HostRiskProfile]:
        """Analyse a fleet of hosts and return risk profiles."""
        profiles: list[HostRiskProfile] = []
        feature_matrix: list[list[float]] = []

        for host in hosts:
            profile = self._score_host(host)
            profiles.append(profile)
            feature_matrix.append(self._host_to_features(host, profile))

        # Fit the detector on the fleet and flag outliers
        if len(feature_matrix) >= 5:
            self._detector.fit(feature_matrix)
            self._baseline_fitted = True
            for profile, features in zip(profiles, feature_matrix):
                result = self._detector.score(features)
                profile.anomaly_score = result.score
                if result.is_anomaly:
                    profile.findings.append(Finding(
                        title="Anomalous host profile",
                        description=(
                            f"Host {profile.host_ip} deviates significantly from fleet baseline "
                            f"(anomaly score: {result.score:.2f})"
                        ),
                        severity=Severity.HIGH,
                        host=profile.host_ip,
                        recommendation="Investigate this host for compromise or misconfiguration.",
                    ))
                    # Bump risk score
                    profile.risk_score = min(1.0, profile.risk_score + 0.2)

        # Sort by risk descending
        profiles.sort(key=lambda p: p.risk_score, reverse=True)
        return profiles

    def score_single(self, host: Host) -> HostRiskProfile:
        """Score a single host (without fleet comparison)."""
        return self._score_host(host)

    # -- Internal -------------------------------------------------------

    def _score_host(self, host: Host) -> HostRiskProfile:
        findings: list[Finding] = []
        risk_scores: list[float] = []
        high_risk: list[str] = []

        for port in host.open_ports:
            if port in _PORT_RISK_DB:
                service, base_risk, issues = _PORT_RISK_DB[port]
                risk_scores.append(base_risk)
                if base_risk >= 0.6:
                    high_risk.append(f"{service} (port {port})")
                self._add_port_findings(findings, host.ip, port, service, base_risk, issues)
            else:
                risk_scores.append(0.3)  # unknown service

        # Excessive open ports
        if len(host.open_ports) > _EXCESSIVE_PORT_THRESHOLD:
            findings.append(Finding(
                title="Excessive open ports",
                description=f"{len(host.open_ports)} open ports detected (threshold: {_EXCESSIVE_PORT_THRESHOLD})",
                severity=Severity.MEDIUM,
                host=host.ip,
                recommendation="Reduce attack surface by closing unnecessary ports.",
            ))

        composite = self._compute_risk_score(risk_scores, host)

        return HostRiskProfile(
            host_ip=host.ip,
            risk_score=round(composite, 3),
            open_port_count=len(host.open_ports),
            high_risk_services=high_risk,
            findings=findings,
        )

    @staticmethod
    def _severity_for_risk(base_risk: float) -> Severity:
        if base_risk >= 0.7:
            return Severity.HIGH
        if base_risk >= 0.4:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _add_port_findings(
        findings: list[Finding], host_ip: str, port: int,
        service: str, base_risk: float, issues: list[str],
    ) -> None:
        sev = NetworkAuditAnalyzer._severity_for_risk(base_risk)
        for issue in issues:
            findings.append(Finding(
                title=f"{service}: {issue}",
                description=f"Port {port}/{service} — {issue}",
                severity=sev,
                host=host_ip,
                port=port,
                recommendation=f"Review {service} configuration on port {port}.",
            ))

    @staticmethod
    def _compute_risk_score(risk_scores: list[float], host: Host) -> float:
        if risk_scores:
            max_risk = max(risk_scores)
            avg_risk = sum(risk_scores) / len(risk_scores)
            breadth = min(len(risk_scores) / 10.0, 0.3)
            return min(1.0, max_risk * 0.6 + avg_risk * 0.25 + breadth * 0.15)
        return 0.0 if host.status == HostStatus.DOWN else 0.1

    @staticmethod
    def _host_to_features(host: Host, profile: HostRiskProfile) -> list[float]:
        """Convert a host + profile into a numeric feature vector for ML."""
        return [
            float(len(host.open_ports)),
            profile.risk_score,
            float(len(profile.high_risk_services)),
            float(len(profile.findings)),
            1.0 if host.status == HostStatus.UP else 0.0,
            # Port diversity: count of distinct well-known vs. high ports
            float(sum(1 for p in host.open_ports if p < 1024)),
            float(sum(1 for p in host.open_ports if p >= 1024)),
        ]
