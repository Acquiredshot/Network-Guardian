"""Network Guardian — Field Agent (Probe)

Standalone lightweight agent that runs on any machine connected to a network.
Performs WiFi scanning, network discovery, and basic system metrics collection,
then reports results back to the base station (mothership).

Each agent is tagged with a unique ID and can be packaged as an executable
for deployment on USB drives.
"""

from network_guardian.agent.probe import (
    AgentIdentity,
    AgentReport,
    build_report,
    scan_wifi,
    discover_hosts,
    collect_system_metrics,
    main,
)

__all__ = [
    "AgentIdentity",
    "AgentReport",
    "build_report",
    "scan_wifi",
    "discover_hosts",
    "collect_system_metrics",
    "main",
]
