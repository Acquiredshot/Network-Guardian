# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Mask Network — Network/Asset Intelligence pillar of the Wolf-Pak Platform.

Mask Network provides the discovery, mapping, and assessment layer that feeds
the Wolf-Pak Security Core:
- Asset discovery (active + passive, subnet sweep, service fingerprinting)
- Threat mapping (external intel feed correlation, IOC matching)
- Vulnerability assessment (port/service exposure scoring, CVE proximity)

Pipeline:
    Mask Network discovery ──► Security Graph (asset + relationship nodes)
                                    │
                                    ▼
                          Threat Intel (IOC + CVE correlation)
"""

__version__ = "0.1.0"
__author__ = "Wolf-Pak Innovations LLC"

__all__ = [
    "AssetDiscovery",
    "ThreatMapper",
    "VulnAssessor",
    "Asset",
    "ThreatMapping",
    "Vulnerability",
]
