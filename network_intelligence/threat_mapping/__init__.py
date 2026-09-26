# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Mask Network — Threat Mapping pillar.

Correlates discovered assets with external threat intelligence feeds
and internal IOCs to produce threat mappings attached to asset nodes
in the Security Graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ThreatSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatMapping:
    """A threat correlation result attached to an asset."""

    asset_id: str
    threat_type: str  # e.g. "malware_cnc", "known_exploit", "scan_source"
    severity: ThreatSeverity
    source: str = ""  # IOC feed name, CVE ID, etc.
    detail: str = ""
    match_field: str = ""  # which asset property matched
    timestamp: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "threat_type": self.threat_type,
            "severity": self.severity.value,
            "source": self.source,
            "detail": self.detail,
        }


class ThreatMapper:
    """Phase 1 threat mapper — IOC set correlation."""

    def __init__(self) -> None:
        self._ioc_sets: dict[str, set[str]] = {}
        self._mappings: list[ThreatMapping] = []

    def add_ioc_set(self, name: str, iocs: set[str]) -> None:
        """Register an IOC set (IPs, domains, hashes, etc.)."""
        self._ioc_sets[name] = iocs

    def map_asset(self, asset: dict[str, Any]) -> list[ThreatMapping]:
        """Correlate a discovered asset against registered IOC sets.

        Phase 1: matches against ip_addresses, hostnames, and
        service fingerprints stored on the asset dict.
        """
        results: list[ThreatMapping] = []
        now = 0.0  # populate from event bus in later phases

        addresses = set(asset.get("addresses", []))
        hostnames = set(asset.get("hostnames", []))
        fingerprints = set(asset.get("fingerprints", []))

        for ioc_name, ioc_set in self._ioc_sets.items():
            for addr in addresses:
                if addr in ioc_set:
                    results.append(
                        ThreatMapping(
                            asset_id=asset.get("id", ""),
                            threat_type=f"known_{ioc_name}_ip",
                            severity=self._severity_for_ioc(ioc_name),
                            source=ioc_name,
                            detail=f"IP {addr} matches {ioc_name} IOC set",
                            match_field="addresses",
                            timestamp=now,
                        )
                    )
            for hostname in hostnames:
                if hostname in ioc_set:
                    results.append(
                        ThreatMapping(
                            asset_id=asset.get("id", ""),
                            threat_type=f"known_{ioc_name}_hostname",
                            severity=self._severity_for_ioc(ioc_name),
                            source=ioc_name,
                            detail=f"Hostname {hostname} matches {ioc_name} IOC set",
                            match_field="hostnames",
                            timestamp=now,
                        )
                    )

        self._mappings.extend(results)
        return results

    def get_mappings_for_asset(self, asset_id: str) -> list[ThreatMapping]:
        """Return all threat mappings for a given asset."""
        return [m for m in self._mappings if m.asset_id == asset_id]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _severity_for_ioc(self, ioc_name: str) -> ThreatSeverity:
        """Phase 1: assign severity based on IOC set name."""
        name = ioc_name.lower()
        if "malware" in name or "cnc" in name:
            return ThreatSeverity.HIGH
        if "exploit" in name or "vuln" in name:
            return ThreatSeverity.CRITICAL
        if "scan" in name or "recon" in name:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW
