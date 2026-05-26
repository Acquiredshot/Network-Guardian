# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Intrusion Detection System (IDS) — signature & anomaly-based detection.

Analyses network traffic patterns, log entries, and event streams to
identify malicious activity.  Supports two detection modes:

  • **Signature-based** — matches traffic against a database of known
    attack patterns (Snort-style rules).
  • **Anomaly-based** — uses statistical baselines and the AI anomaly
    engine to flag deviations from normal behaviour.

All detections are published on the event bus so other subsystems
(IPS, dashboard, logger) can react.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus
from network_guardian.models.network import Severity

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.ids")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ThreatCategory(Enum):
    """Classification of detected threats."""

    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DOS = "denial_of_service"
    MALWARE = "malware"
    DATA_EXFIL = "data_exfiltration"
    INJECTION = "injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    POLICY_VIOLATION = "policy_violation"
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"


class DetectionMethod(Enum):
    SIGNATURE = "signature"
    ANOMALY = "anomaly"
    HEURISTIC = "heuristic"
    CORRELATION = "correlation"


@dataclass
class SignatureRule:
    """A signature-based detection rule (Snort-style)."""

    sid: int
    name: str
    pattern: str  # regex pattern
    category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: Severity = Severity.MEDIUM
    description: str = ""
    enabled: bool = True
    _compiled: re.Pattern[str] | None = field(default=None, repr=False)

    @property
    def compiled(self) -> re.Pattern[str]:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled


@dataclass
class Alert:
    """An IDS alert representing a detected threat."""

    alert_id: str
    rule_name: str
    category: ThreatCategory
    severity: Severity
    source_ip: str
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    method: DetectionMethod = DetectionMethod.SIGNATURE
    description: str = ""
    raw_data: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "method": self.method.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Default signature rules
# ---------------------------------------------------------------------------

_DEFAULT_RULES: list[SignatureRule] = [
    # -- Reconnaissance --
    SignatureRule(
        sid=1001, name="TCP SYN Scan",
        pattern=r"SYN.*(?:scan|probe)",
        category=ThreatCategory.PORT_SCAN,
        severity=Severity.LOW,
        description="Detected TCP SYN scan activity.",
    ),
    SignatureRule(
        sid=1002, name="ICMP Sweep",
        pattern=r"ICMP.*(?:sweep|ping\s+scan)",
        category=ThreatCategory.RECONNAISSANCE,
        severity=Severity.LOW,
        description="ICMP sweep targeting multiple hosts.",
    ),
    SignatureRule(
        sid=1003, name="Service Enumeration",
        pattern=r"(?:nmap|masscan|zmap).*(?:-sV|-sC|version)",
        category=ThreatCategory.RECONNAISSANCE,
        severity=Severity.MEDIUM,
        description="Service/version enumeration detected.",
    ),
    # -- Brute Force --
    SignatureRule(
        sid=2001, name="SSH Brute Force",
        pattern=r"(?:ssh|port\s*22).*(?:fail|invalid|denied){3,}",
        category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.HIGH,
        description="Multiple SSH authentication failures detected.",
    ),
    SignatureRule(
        sid=2002, name="Login Brute Force",
        pattern=r"(?:login|auth).*(?:fail|invalid|wrong).*(?:attempt|tries)",
        category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.HIGH,
        description="Repeated login failures indicating brute-force attack.",
    ),
    # -- Injection --
    SignatureRule(
        sid=3001, name="SQL Injection Attempt",
        pattern=r"(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*--)",
        category=ThreatCategory.INJECTION,
        severity=Severity.CRITICAL,
        description="SQL injection payload detected in request.",
    ),
    SignatureRule(
        sid=3002, name="Command Injection Attempt",
        pattern=r"(?:;\s*(?:cat|ls|id|whoami|wget|curl)\b|\|\s*(?:bash|sh|cmd))",
        category=ThreatCategory.INJECTION,
        severity=Severity.CRITICAL,
        description="OS command injection attempt detected.",
    ),
    SignatureRule(
        sid=3003, name="XSS Attempt",
        pattern=r"<script[^>]*>|javascript:|on(?:error|load|click)\s*=",
        category=ThreatCategory.INJECTION,
        severity=Severity.HIGH,
        description="Cross-site scripting payload detected.",
    ),
    # -- Denial of Service --
    SignatureRule(
        sid=4001, name="SYN Flood",
        pattern=r"SYN\s+flood|syn_flood|too\s+many\s+SYN",
        category=ThreatCategory.DOS,
        severity=Severity.CRITICAL,
        description="SYN flood denial-of-service attack detected.",
    ),
    # -- Malware / C2 --
    SignatureRule(
        sid=5001, name="Known Malware Signature",
        pattern=r"(?:trojan|ransomware|worm|backdoor).*(?:detected|found|payload)",
        category=ThreatCategory.MALWARE,
        severity=Severity.CRITICAL,
        description="Known malware signature matched.",
    ),
    SignatureRule(
        sid=5002, name="C2 Beacon Pattern",
        pattern=r"(?:beacon|callback|heartbeat).*(?:interval|periodic|c2|command.and.control)",
        category=ThreatCategory.C2_COMMUNICATION,
        severity=Severity.HIGH,
        description="Command-and-control beacon pattern detected.",
    ),
    # -- Data Exfiltration --
    SignatureRule(
        sid=6001, name="DNS Tunnelling",
        pattern=r"dns.*(?:tunnel|exfil|encoded|base64).*(?:query|request)",
        category=ThreatCategory.DATA_EXFIL,
        severity=Severity.HIGH,
        description="Possible DNS tunnelling for data exfiltration.",
    ),
    SignatureRule(
        sid=6002, name="Large Outbound Transfer",
        pattern=r"(?:upload|outbound|egress).*(?:large|excessive|abnormal).*(?:bytes|data|transfer)",
        category=ThreatCategory.DATA_EXFIL,
        severity=Severity.MEDIUM,
        description="Unusually large outbound data transfer detected.",
    ),
    # -- Privilege Escalation --
    SignatureRule(
        sid=7001, name="Privilege Escalation Attempt",
        pattern=r"(?:sudo|su\s|runas|privilege).*(?:escal|elevat|root|admin)",
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        severity=Severity.HIGH,
        description="Privilege escalation attempt detected.",
    ),
    # -- Lateral Movement --
    SignatureRule(
        sid=8001, name="Lateral Movement via SMB",
        pattern=r"(?:smb|port\s*445).*(?:lateral|spread|psexec|wmi)",
        category=ThreatCategory.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        description="Lateral movement via SMB/WMI detected.",
    ),
]


# ---------------------------------------------------------------------------
# Anomaly-based detection engine
# ---------------------------------------------------------------------------


class ConnectionTracker:
    """Tracks connection patterns per source IP for anomaly detection."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window = window_seconds
        self._connections: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=10_000)
        )
        self._port_sets: dict[str, set[int]] = defaultdict(set)

    def record(self, source_ip: str, dest_port: int = 0) -> None:
        """Record a connection event."""
        now = time.monotonic()
        self._connections[source_ip].append(now)
        if dest_port:
            self._port_sets[source_ip].add(dest_port)

    def _prune(self, source_ip: str) -> list[float]:
        """Return timestamps within the detection window."""
        now = time.monotonic()
        cutoff = now - self.window
        q = self._connections.get(source_ip, deque())
        recent = [t for t in q if t >= cutoff]
        return recent

    def connection_rate(self, source_ip: str) -> float:
        """Connections per second in the current window."""
        recent = self._prune(source_ip)
        if len(recent) < 2:
            return 0.0
        span = recent[-1] - recent[0]
        return len(recent) / span if span > 0 else float(len(recent))

    def unique_ports(self, source_ip: str) -> int:
        """Number of unique destination ports contacted."""
        return len(self._port_sets.get(source_ip, set()))

    def reset(self, source_ip: str | None = None) -> None:
        """Reset tracking for one or all IPs."""
        if source_ip:
            self._connections.pop(source_ip, None)
            self._port_sets.pop(source_ip, None)
        else:
            self._connections.clear()
            self._port_sets.clear()


# ---------------------------------------------------------------------------
# Intrusion Detection System
# ---------------------------------------------------------------------------


class IntrusionDetectionSystem:
    """Signature + anomaly-based intrusion detection engine.

    Analyses traffic data, log entries, and connection metadata to
    detect known attack patterns and behavioural anomalies.
    """

    # Anomaly thresholds
    PORT_SCAN_THRESHOLD = 20        # unique ports in window → port scan
    CONNECTION_RATE_THRESHOLD = 50  # conns/sec → DoS or brute force
    BRUTE_FORCE_FAILURES = 5        # auth failures in window

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus

        self._rules: list[SignatureRule] = copy.deepcopy(_DEFAULT_RULES)
        self._tracker = ConnectionTracker(window_seconds=60.0)
        self._alerts: list[Alert] = []
        self._alert_counter = 0
        self._auth_failures: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=100)
        )
        self._running = False
        self._suppressed: dict[str, float] = {}
        self._suppression_window = 30.0  # seconds between duplicate alerts

    # -- Rule management ------------------------------------------------

    @property
    def rules(self) -> list[SignatureRule]:
        return list(self._rules)

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts)

    def add_rule(self, rule: SignatureRule) -> None:
        """Add a custom signature rule."""
        self._rules.append(rule)
        logger.info("Added IDS rule SID=%d: %s", rule.sid, rule.name)

    def remove_rule(self, sid: int) -> bool:
        """Remove a rule by SID. Returns True if found."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.sid != sid]
        return len(self._rules) < before

    def enable_rule(self, sid: int) -> bool:
        for r in self._rules:
            if r.sid == sid:
                r.enabled = True
                return True
        return False

    def disable_rule(self, sid: int) -> bool:
        for r in self._rules:
            if r.sid == sid:
                r.enabled = False
                return True
        return False

    # -- Alert generation -----------------------------------------------

    def _generate_alert_id(self) -> str:
        self._alert_counter += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"IDS-{ts}-{self._alert_counter:04d}"

    def _is_suppressed(self, key: str) -> bool:
        """Check if an alert with this key was recently fired."""
        now = time.monotonic()
        last = self._suppressed.get(key)
        if last is not None and (now - last) < self._suppression_window:
            return True
        self._suppressed[key] = now
        return False

    async def _fire_alert(self, alert: Alert) -> None:
        """Record the alert and publish on the event bus."""
        suppress_key = f"{alert.rule_name}:{alert.source_ip}"
        if self._is_suppressed(suppress_key):
            logger.debug("Alert suppressed (duplicate window): %s", suppress_key)
            return

        self._alerts.append(alert)
        # Cap stored alerts
        if len(self._alerts) > 10_000:
            self._alerts = self._alerts[-5_000:]

        logger.warning(
            "IDS ALERT [%s] %s — %s (src=%s dst=%s) severity=%s",
            alert.alert_id, alert.rule_name, alert.category.value,
            alert.source_ip, alert.destination_ip, alert.severity.value,
        )
        await self.event_bus.publish(Event(
            topic="ids.alert",
            data={"alert": alert.as_dict},
        ))

    # -- Signature-based detection --------------------------------------

    async def analyse_payload(
        self,
        payload: str,
        source_ip: str = "unknown",
        destination_ip: str = "",
        source_port: int = 0,
        destination_port: int = 0,
    ) -> list[Alert]:
        """Scan payload text against all enabled signature rules."""
        triggered: list[Alert] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.compiled.search(payload):
                alert = Alert(
                    alert_id=self._generate_alert_id(),
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    source_port=source_port,
                    destination_port=destination_port,
                    method=DetectionMethod.SIGNATURE,
                    description=rule.description,
                    raw_data=payload[:500],
                )
                await self._fire_alert(alert)
                triggered.append(alert)
        return triggered

    # -- Anomaly-based detection ----------------------------------------

    async def record_connection(
        self,
        source_ip: str,
        destination_ip: str = "",
        destination_port: int = 0,
    ) -> list[Alert]:
        """Record a connection event and check for anomalies."""
        self._tracker.record(source_ip, destination_port)
        triggered: list[Alert] = []

        # Check for port scan
        unique = self._tracker.unique_ports(source_ip)
        if unique >= self.PORT_SCAN_THRESHOLD:
            alert = Alert(
                alert_id=self._generate_alert_id(),
                rule_name="Port Scan Detected",
                category=ThreatCategory.PORT_SCAN,
                severity=Severity.MEDIUM,
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                method=DetectionMethod.ANOMALY,
                description=f"Source contacted {unique} unique ports in {self._tracker.window}s.",
                metadata={"unique_ports": unique},
            )
            await self._fire_alert(alert)
            triggered.append(alert)

        # Check for connection flood (DoS)
        rate = self._tracker.connection_rate(source_ip)
        if rate >= self.CONNECTION_RATE_THRESHOLD:
            alert = Alert(
                alert_id=self._generate_alert_id(),
                rule_name="Connection Flood",
                category=ThreatCategory.DOS,
                severity=Severity.HIGH,
                source_ip=source_ip,
                destination_ip=destination_ip,
                method=DetectionMethod.ANOMALY,
                description=f"Connection rate {rate:.1f}/s exceeds threshold.",
                metadata={"rate": rate},
            )
            await self._fire_alert(alert)
            triggered.append(alert)

        return triggered

    async def record_auth_failure(
        self, source_ip: str, service: str = "unknown",
    ) -> list[Alert]:
        """Record an authentication failure and check for brute-force."""
        now = time.monotonic()
        q = self._auth_failures[source_ip]
        q.append(now)

        # Count failures in window
        cutoff = now - self._tracker.window
        recent = [t for t in q if t >= cutoff]
        triggered: list[Alert] = []

        if len(recent) >= self.BRUTE_FORCE_FAILURES:
            alert = Alert(
                alert_id=self._generate_alert_id(),
                rule_name="Brute Force Detected",
                category=ThreatCategory.BRUTE_FORCE,
                severity=Severity.HIGH,
                source_ip=source_ip,
                method=DetectionMethod.HEURISTIC,
                description=(
                    f"{len(recent)} auth failures for {service} "
                    f"in {self._tracker.window}s."
                ),
                metadata={"service": service, "failures": len(recent)},
            )
            await self._fire_alert(alert)
            triggered.append(alert)

        return triggered

    # -- Correlation engine ---------------------------------------------

    async def correlate_events(
        self, events: list[dict[str, Any]],
    ) -> list[Alert]:
        """Analyse a batch of events for multi-stage attack patterns.

        Checks for reconnaissance → exploitation chains by correlating
        events from the same source within a time window.
        """
        triggered: list[Alert] = []
        # Group events by source IP
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for evt in events:
            src = evt.get("source_ip", "unknown")
            by_source[src].append(evt)

        for src_ip, src_events in by_source.items():
            categories = {e.get("category", "") for e in src_events}
            # Recon followed by injection = attack chain
            recon = categories & {"port_scan", "reconnaissance"}
            exploit = categories & {"injection", "brute_force", "privilege_escalation"}
            if recon and exploit:
                alert = Alert(
                    alert_id=self._generate_alert_id(),
                    rule_name="Multi-Stage Attack Chain",
                    category=ThreatCategory.LATERAL_MOVEMENT,
                    severity=Severity.CRITICAL,
                    source_ip=src_ip,
                    method=DetectionMethod.CORRELATION,
                    description=(
                        f"Correlated recon ({', '.join(recon)}) + exploit "
                        f"({', '.join(exploit)}) from same source."
                    ),
                    metadata={"stages": list(recon | exploit)},
                )
                await self._fire_alert(alert)
                triggered.append(alert)

        return triggered

    # -- Lifecycle ------------------------------------------------------

    async def start(self) -> None:
        """Start the IDS engine."""
        self._running = True
        logger.info(
            "IDS started: %d signature rules loaded, anomaly detection active.",
            sum(1 for r in self._rules if r.enabled),
        )
        await self.event_bus.publish(Event(
            topic="ids.started",
            data={"rules_loaded": len(self._rules)},
        ))

    async def stop(self) -> None:
        """Stop the IDS engine."""
        self._running = False
        self._tracker.reset()
        logger.info("IDS stopped. %d total alerts generated.", len(self._alerts))

    def clear_alerts(self) -> int:
        """Clear alert history. Returns number cleared."""
        count = len(self._alerts)
        self._alerts.clear()
        self._alert_counter = 0
        return count

    @property
    def stats(self) -> dict[str, Any]:
        """Return IDS statistics."""
        by_severity: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        for a in self._alerts:
            by_severity[a.severity.value] += 1
            by_category[a.category.value] += 1

        return {
            "total_alerts": len(self._alerts),
            "rules_loaded": len(self._rules),
            "rules_enabled": sum(1 for r in self._rules if r.enabled),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "running": self._running,
        }
