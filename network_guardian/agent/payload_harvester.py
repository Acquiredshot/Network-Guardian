# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Payload Harvester — Learning from Successful Exploitations

When the probe successfully exploits a vulnerability, the harvester:
  1. Extracts payload patterns
  2. Converts to regex-based detection rules
  3. Assigns confidence scores based on exploitation context
  4. Feeds into the smart firewall's dynamic rule set

This enables the firewall to detect similar attacks based on real-world
exploitation patterns discovered during network reconnaissance.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from network_guardian.agent.smart_firewall_agent import InjectionRule, InjectionType

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.payload_harvester")


@dataclass
class HarvestedRule:
    """Record of a rule created from exploited payload."""
    rule_name: str
    pattern: str
    injection_type: str
    severity: str
    base_confidence: float
    source_vuln_type: str
    source_ip: str | None
    target_ip: str
    created_at: str
    successful_detections: int = 0
    failed_detections: int = 0


class PayloadHarvester:
    """
    Converts exploited payloads into firewall detection rules.

    Maintains a registry of harvested rules, prevents duplication,
    and tracks their effectiveness.
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        event_bus: EventBus | None = None,
    ):
        self._data_dir = data_dir or Path.home() / ".network_guardian" / "payload_harvester"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._event_bus = event_bus

        self._harvested_rules: dict[str, HarvestedRule] = {}
        self._payload_patterns: dict[str, list[str]] = {}
        self._load_harvested_rules()

    def harvest_from_exploitation(
        self,
        payload: str,
        vuln_type: str,
        source_ip: str | None,
        target_ip: str,
    ) -> InjectionRule | None:
        """
        Harvest a detection rule from successfully exploited payload.

        Args:
            payload: Raw payload that triggered vulnerability
            vuln_type: Type of vulnerability ("soap_auth_bypass", "xss", "sql_injection", etc.)
            source_ip: IP that performed exploitation (None if internal)
            target_ip: Target that was exploited

        Returns:
            Created InjectionRule or None if harvesting failed
        """
        if not payload or len(payload) < 5:
            logger.debug(f"Payload too short to harvest: {len(payload)} chars")
            return None

        logger.info(f"Harvesting rule from {vuln_type} exploitation on {target_ip}")

        pattern = self._generate_detection_pattern(payload, vuln_type)
        if not pattern:
            logger.warning(f"Failed to generate pattern for {vuln_type}")
            return None

        injection_type = self._map_vuln_to_injection_type(vuln_type)
        confidence = self._calculate_confidence_from_context(vuln_type)

        rule_name = f"HARVESTED-{vuln_type.upper()}-{len(self._harvested_rules) + 1}"

        rule = InjectionRule(
            name=rule_name,
            pattern=pattern,
            injection_type=injection_type,
            severity=self._severity_for_vuln_type(vuln_type),
            confidence=confidence,
            description=f"Harvested from {vuln_type} exploitation on {target_ip}",
            enabled=True,
        )

        harvested = HarvestedRule(
            rule_name=rule_name,
            pattern=pattern,
            injection_type=injection_type.value,
            severity=rule.severity,
            base_confidence=confidence,
            source_vuln_type=vuln_type,
            source_ip=source_ip,
            target_ip=target_ip,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        self._harvested_rules[rule_name] = harvested
        self._persist_harvested_rules()

        logger.info(f"Created rule {rule_name}: confidence={confidence:.2f}")

        return rule

    def _generate_detection_pattern(self, payload: str, vuln_type: str) -> str | None:
        """
        Convert exploited payload into a regex detection pattern.

        Escapes special characters and creates a pattern that:
        - Matches the core payload elements
        - Avoids exact matching (handles encoding variations)
        - Maintains reasonable specificity
        """
        vuln_type_lower = vuln_type.lower()

        if "soap" in vuln_type_lower:
            return self._pattern_from_soap(payload)
        elif "xss" in vuln_type_lower:
            return self._pattern_from_xss(payload)
        elif "sql" in vuln_type_lower:
            return self._pattern_from_sql(payload)
        elif "auth" in vuln_type_lower:
            return self._pattern_from_auth(payload)
        elif "command" in vuln_type_lower or "cmd" in vuln_type_lower or "shell" in vuln_type_lower:
            return self._pattern_from_cmd(payload)
        else:
            return self._pattern_generic(payload)

    def _pattern_from_soap(self, payload: str) -> str:
        """Extract SOAP-specific pattern."""
        patterns = []
        for tag in ["ConfigurationStarted", "SetPassword", "SetWLANSSIDBroadcast", "Authenticate"]:
            if tag in payload:
                patterns.append(re.escape(tag))

        if patterns:
            return "|".join(patterns)
        return re.escape(payload[:50])

    def _pattern_from_xss(self, payload: str) -> str:
        """Extract XSS-specific pattern."""
        if "<script" in payload.lower():
            return r"<\s*script[^>]*>"
        if "javascript:" in payload.lower():
            return r"javascript\s*:"
        if "onerror" in payload.lower() or "onload" in payload.lower():
            return r"\bon(?:error|load|click)\s*="

        return re.escape(payload[:40])

    def _pattern_from_sql(self, payload: str) -> str:
        """Extract SQL-specific pattern."""
        if "union" in payload.lower() and "select" in payload.lower():
            return r"union\s+(?:all\s+)?select"
        if "or 1=1" in payload.lower():
            return r"(?:'|\")\s*(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"
        if ";" in payload:
            return r";\s*(?:drop|insert|update|delete|alter|create|exec)"

        return re.escape(payload[:50])

    def _pattern_from_auth(self, payload: str) -> str:
        """Extract authentication bypass pattern."""
        if "admin" in payload.lower():
            return r"admin|username"
        if "password" in payload.lower():
            return r"password|passwd"

        return re.escape(payload[:50])

    def _pattern_from_cmd(self, payload: str) -> str:
        """Extract command injection pattern."""
        dangerous_cmds = [
            "cat", "ls", "id", "whoami", "uname", "passwd",
            "wget", "curl", "nc", "bash", "sh", "cmd", "powershell"
        ]
        for cmd in dangerous_cmds:
            if cmd in payload.lower():
                return rf"(?:[|;`]|\$\()\s*(?:{cmd}|[\w/]+)\b"

        return r"(?:[|;`]|\$\()"

    def _pattern_generic(self, payload: str) -> str:
        """Generic pattern from payload."""
        if len(payload) > 100:
            return re.escape(payload[:50])
        return re.escape(payload)

    def _map_vuln_to_injection_type(self, vuln_type: str) -> InjectionType:
        """Map vulnerability type to InjectionType enum."""
        vuln_lower = vuln_type.lower()

        if "soap" in vuln_lower or "auth" in vuln_lower:
            return InjectionType.HEADER
        elif "xss" in vuln_lower:
            return InjectionType.XSS
        elif "sql" in vuln_lower:
            return InjectionType.SQL
        elif "command" in vuln_lower or "cmd" in vuln_lower or "shell" in vuln_lower:
            return InjectionType.CMD
        elif "path" in vuln_lower:
            return InjectionType.PATH_TRAVERSAL
        elif "ldap" in vuln_lower:
            return InjectionType.LDAP
        elif "xxe" in vuln_lower:
            return InjectionType.XXE
        elif "ssti" in vuln_lower:
            return InjectionType.SSTI
        elif "nosql" in vuln_lower:
            return InjectionType.NOSQL
        elif "graphql" in vuln_lower:
            return InjectionType.GRAPHQL
        else:
            return InjectionType.UNKNOWN

    def _calculate_confidence_from_context(self, vuln_type: str) -> float:
        """
        Calculate initial confidence for harvested rule.

        Higher confidence for vulnerabilities that are harder to exploit.
        """
        base_confidence_map = {
            "soap_auth_bypass": 0.88,
            "sql_injection": 0.85,
            "xss": 0.80,
            "command_injection": 0.90,
            "ldap_injection": 0.78,
            "xxe": 0.92,
            "ssti": 0.85,
            "path_traversal": 0.82,
            "header_injection": 0.80,
            "nosql_injection": 0.83,
            "graphql_injection": 0.75,
        }

        return base_confidence_map.get(vuln_type.lower(), 0.75)

    def _severity_for_vuln_type(self, vuln_type: str) -> str:
        """Map vulnerability type to severity level."""
        vuln_lower = vuln_type.lower()

        if any(x in vuln_lower for x in ["xxe", "rce", "command", "sql"]):
            return "critical"
        elif any(x in vuln_lower for x in ["xss", "soap", "ldap"]):
            return "high"
        else:
            return "medium"

    def record_detection(self, rule_name: str, success: bool) -> None:
        """Track detection results for harvested rules."""
        if rule_name not in self._harvested_rules:
            return

        if success:
            self._harvested_rules[rule_name].successful_detections += 1
        else:
            self._harvested_rules[rule_name].failed_detections += 1

        self._persist_harvested_rules()

    def get_harvested_rules(self) -> list[HarvestedRule]:
        """Get all harvested rules."""
        return list(self._harvested_rules.values())

    def _load_harvested_rules(self) -> None:
        """Load harvested rules from disk."""
        rules_file = self._data_dir / "harvested_rules.json"
        if not rules_file.exists():
            return

        try:
            data = json.loads(rules_file.read_text())
            for rule_name, rule_data in data.items():
                self._harvested_rules[rule_name] = HarvestedRule(**rule_data)
            logger.info(f"Loaded {len(self._harvested_rules)} harvested rules from disk")
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.warning(f"Failed to load harvested rules: {e}")

    def _persist_harvested_rules(self) -> None:
        """Save harvested rules to disk."""
        rules_file = self._data_dir / "harvested_rules.json"
        try:
            data = {
                name: asdict(rule)
                for name, rule in self._harvested_rules.items()
            }
            rules_file.write_text(json.dumps(data, indent=2, default=str))
        except OSError as e:
            logger.error(f"Failed to persist harvested rules: {e}")

    def get_stats(self) -> dict:
        """Get harvester statistics."""
        rules = self._harvested_rules.values()
        total_detections = sum(r.successful_detections + r.failed_detections for r in rules)

        return {
            "total_harvested_rules": len(self._harvested_rules),
            "total_detections": total_detections,
            "avg_successful_rate": (
                sum(r.successful_detections for r in rules) / max(total_detections, 1)
            ),
            "injection_types": list(set(r.injection_type for r in rules)),
        }
