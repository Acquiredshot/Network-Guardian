# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Mask Network — Vulnerability Assessment pillar.

Evaluates discovered assets for exposure-based risk:
- Port/service exposure scoring
- Known CVE proximity (phase 2+)
- Attack-surface aggregation

Output: Vulnerability records attached to asset nodes in the Security Graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VulnSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Vulnerability:
    """A single vulnerability finding on an asset."""

    asset_id: str
    vuln_id: str  # e.g. "CVE-2024-XXXX" or internal "EXPOSURE-PORT-22"
    title: str
    severity: VulnSeverity
    description: str = ""
    references: list[str] = field(default_factory=list)
    cvss: float = 0.0  # 0..10
    timestamp: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "vuln_id": self.vuln_id,
            "title": self.title,
            "severity": self.severity.value,
            "cvss": self.cvss,
        }


class VulnAssessor:
    """Phase 1 vulnerability assessor — port/service exposure scoring."""

    # Services considered high-risk when exposed
    HIGH_RISK_SERVICES = {
        23: ("telnet", "Unencrypted remote access — plaintext creds", 8.5),
        21: ("ftp", "Unencrypted file transfer — plaintext creds", 7.5),
        3389: ("rdp", "Remote Desktop — frequent exploit target", 8.0),
        1433: ("mssql", "Microsoft SQL Server — commonly targeted", 7.0),
        1521: ("oracle", "Oracle DB listener — known exploit surface", 7.5),
        3306: ("mysql", "MySQL — brute-force + exploit surface", 6.5),
        5432: ("postgresql", "PostgreSQL — auth misconfig risk", 6.0),
        6379: ("redis", "Redis unauthenticated — critical if exposed", 9.0),
        27017: ("mongodb", "MongoDB unauthenticated — critical if exposed", 9.0),
    }

    MEDIUM_RISK_SERVICES = {
        22: ("ssh", "SSH — strong auth mitigates; weak creds/old versions risky", 5.0),
        80: ("http", "HTTP — depends on hosted app security posture", 4.0),
        443: ("https", "HTTPS — depends on TLS config + app security", 3.5),
        8080: ("http-alt", "HTTP alternate — same risks as port 80", 4.0),
        8443: ("https-alt", "HTTPS alternate — same risks as 443", 3.5),
    }

    def assess_asset(self, asset: dict[str, Any]) -> list[Vulnerability]:
        """Produce vulnerability findings for a discovered asset.

        Phase 1: port/service exposure scoring.
        Phase 2+: CVE lookup, config assessment, auth strength evaluation.
        """
        findings: list[Vulnerability] = []
        open_ports = asset.get("open_ports", [])
        now = 0.0  # populated from event bus in later phases

        for port in open_ports:
            sev, title, desc = self._score_port(port)
            vuln_id = f"EXPOSURE-PORT-{port}"
            findings.append(
                Vulnerability(
                    asset_id=asset.get("id", ""),
                    vuln_id=vuln_id,
                    title=f"{title} on port {port}",
                    severity=sev,
                    description=desc,
                    cvss=self._cvss_from_severity(sev),
                    timestamp=now,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_port(self, port: int) -> tuple[VulnSeverity, str, str]:
        if port in self.HIGH_RISK_SERVICES:
            svc, desc, cvss = self.HIGH_RISK_SERVICES[port]
            return self._severity_from_cvss(cvss), svc, desc
        if port in self.MEDIUM_RISK_SERVICES:
            svc, desc, cvss = self.MEDIUM_RISK_SERVICES[port]
            return self._severity_from_cvss(cvss), svc, desc
        return VulnSeverity.LOW, f"port-{port}", f"Unknown service on port {port}"

    @staticmethod
    def _severity_from_cvss(cvss: float) -> VulnSeverity:
        if cvss >= 9.0:
            return VulnSeverity.CRITICAL
        if cvss >= 7.0:
            return VulnSeverity.HIGH
        if cvss >= 4.0:
            return VulnSeverity.MEDIUM
        return VulnSeverity.LOW

    @staticmethod
    def _cvss_from_severity(sev: VulnSeverity) -> float:
        return {
            VulnSeverity.CRITICAL: 9.5,
            VulnSeverity.HIGH: 7.5,
            VulnSeverity.MEDIUM: 5.0,
            VulnSeverity.LOW: 2.5,
            VulnSeverity.NONE: 0.0,
        }.get(sev, 0.0)
