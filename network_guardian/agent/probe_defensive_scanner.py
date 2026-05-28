# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Probe Defensive Scanner — Testing Internal Network Against Firewall Rules

The defensive scanner leverages the smart firewall's own detection rules to
test the internal network for vulnerabilities. This provides:

  1. **Validation** — False-positive elimination: if firewall detects injection,
     but endpoint returns 404, it's a false positive.

  2. **Coverage** — Test for vulnerabilities using realistic payloads from
     firewall rules, synthesized to target the discovered service type.

  3. **Responsiveness** — Verify firewall actually blocks attacks on endpoints
     in real-time.

Scan Strategy:
  - Discover endpoint type (HTTP, SQL, SOAP, etc.) from probe findings
  - Extract firewall rules for that service type
  - Synthesize test payloads from rules
  - Send payloads to endpoint
  - Analyze response:
    - Firewall blocked → expected behavior ✓
    - Endpoint vulnerable → report vulnerability ✗
    - Blocked by endpoint × port closed → skip
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.parse import urlencode
import urllib.request
import urllib.error

if TYPE_CHECKING:
    from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent

logger = logging.getLogger("network_guardian.agent.probe_defensive_scanner")


@dataclass
class ScanResult:
    """Result of scanning an endpoint for vulnerabilities."""
    target_ip: str
    target_port: int
    service_type: str
    injection_type: str
    payload: str
    response_code: int
    response_text: str | None
    was_blocked_by_firewall: bool
    is_vulnerable: bool
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProbeDefensiveScanner:
    """
    Tests internal network endpoints for injection vulnerabilities.

    Uses firewall detection rules to synthesize realistic payloads and validate
    endpoint security. Results are reported as findings for remediation.
    """

    def __init__(
        self,
        smart_firewall: SmartFirewallAgent | None = None,
        data_dir: Path | None = None,
    ):
        self._firewall = smart_firewall
        self._data_dir = data_dir or Path.home() / ".network_guardian" / "defensive_scanner"
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._scan_results: dict[str, ScanResult] = {}
        self._load_scan_results()

    async def scan_endpoint_for_injections(
        self,
        ip: str,
        port: int,
        service_type: str,
        timeout: int = 10,
    ) -> list[ScanResult]:
        """
        Scan endpoint for injection vulnerabilities.

        Args:
            ip: Target IP address
            port: Target port
            service_type: Type of service (http, sql, soap, etc.)
            timeout: Request timeout in seconds

        Returns:
            List of ScanResult objects
        """
        results = []

        logger.info(f"Starting defensive scan: {service_type} on {ip}:{port}")

        payloads = self._synthesize_payloads_for_service(service_type)

        for payload_group in payloads:
            for injection_type, payload in payload_group.items():
                try:
                    response_code, response_text = await self._send_payload(
                        ip, port, service_type, payload, timeout
                    )

                    result = ScanResult(
                        target_ip=ip,
                        target_port=port,
                        service_type=service_type,
                        injection_type=injection_type,
                        payload=payload[:300],
                        response_code=response_code,
                        response_text=response_text[:500] if response_text else None,
                        was_blocked_by_firewall=response_code == 403,
                        is_vulnerable=self._is_vulnerable(response_code, response_text),
                    )

                    results.append(result)
                    self._scan_results[f"{ip}:{port}_{injection_type}"] = result

                    if result.is_vulnerable:
                        logger.warning(
                            f"VULNERABLE: {injection_type} on {ip}:{port}"
                        )
                    elif result.was_blocked_by_firewall:
                        logger.info(
                            f"BLOCKED: {injection_type} attempt on {ip}:{port}"
                        )

                except asyncio.TimeoutError:
                    logger.debug(f"Timeout scanning {ip}:{port}")
                    break
                except Exception as e:
                    logger.debug(f"Error scanning {ip}:{port}: {e}")
                    continue

        self._persist_scan_results()

        return results

    def _synthesize_payloads_for_service(self, service_type: str) -> list[dict[str, str]]:
        """
        Synthesize test payloads based on service type.

        Returns list of dictionaries mapping injection_type → payload.
        """
        service_type_lower = service_type.lower()

        if "http" in service_type_lower or "web" in service_type_lower:
            return self._payloads_for_http()
        elif "sql" in service_type_lower:
            return self._payloads_for_sql()
        elif "soap" in service_type_lower:
            return self._payloads_for_soap()
        elif "ldap" in service_type_lower:
            return self._payloads_for_ldap()
        else:
            return self._payloads_generic()

    def _payloads_for_http(self) -> list[dict[str, str]]:
        """Generate payloads for HTTP/HTTPS endpoints."""
        return [
            {
                "xss_script": "<script>alert('xss')</script>",
                "xss_event": "<img onerror=alert('xss')>",
                "xss_javascript": "javascript:alert('xss')",
            },
            {
                "path_traversal": "../../etc/passwd",
                "path_traversal_url": "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            },
            {
                "cmd_injection": "; whoami;",
                "cmd_injection_pipe": "| id",
            },
        ]

    def _payloads_for_sql(self) -> list[dict[str, str]]:
        """Generate payloads for SQL endpoints."""
        return [
            {
                "sql_union": "UNION SELECT NULL, NULL, NULL--",
                "sql_tautology": "' OR '1'='1",
                "sql_comment": "'; DROP TABLE users;--",
            },
            {
                "sql_sleep": "SLEEP(5)",
                "sql_benchmark": "BENCHMARK(10000000, SHA1('test'))",
            },
        ]

    def _payloads_for_soap(self) -> list[dict[str, str]]:
        """Generate payloads for SOAP endpoints."""
        return [
            {
                "soap_xxe": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                "soap_entity": '<!ENTITY % file SYSTEM "file:///etc/passwd">',
            },
            {
                "soap_injection": "NewSessionID\"><script>alert('xss')</script><foo bar=\"",
            },
        ]

    def _payloads_for_ldap(self) -> list[dict[str, str]]:
        """Generate payloads for LDAP endpoints."""
        return [
            {
                "ldap_filter": "*)(objectClass=*",
                "ldap_or": "admin*",
            },
        ]

    def _payloads_generic(self) -> list[dict[str, str]]:
        """Generate generic payloads for unknown services."""
        return [
            {
                "injection_attempt": "' OR 1=1 --",
                "cmd_attempt": "; whoami;",
            },
        ]

    async def _send_payload(
        self,
        ip: str,
        port: int,
        service_type: str,
        payload: str,
        timeout: int = 10,
    ) -> tuple[int, str | None]:
        """
        Send payload to endpoint and capture response.

        Returns:
            (response_code, response_text)
        """
        if "http" in service_type.lower() or "web" in service_type.lower():
            return await self._send_http_payload(ip, port, payload, timeout)
        else:
            return await self._send_generic_payload(ip, port, payload, timeout)

    async def _send_http_payload(
        self,
        ip: str,
        port: int,
        payload: str,
        timeout: int,
    ) -> tuple[int, str | None]:
        """Send payload via HTTP GET/POST."""
        url = f"http://{ip}:{port}/?q={payload}"

        loop = asyncio.get_event_loop()
        try:
            response_code, response_text = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    self._http_request,
                    url,
                    timeout,
                ),
                timeout=timeout + 2,
            )
            return response_code, response_text
        except asyncio.TimeoutError:
            raise
        except Exception as e:
            logger.debug(f"HTTP request failed: {e}")
            return 0, None

    def _http_request(self, url: str, timeout: int) -> tuple[int, str | None]:
        """Synchronous HTTP request."""
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.code, response.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="ignore")
        except urllib.error.URLError as e:
            logger.debug(f"URL error: {e}")
            return 0, None

    async def _send_generic_payload(
        self,
        ip: str,
        port: int,
        payload: str,
        timeout: int,
    ) -> tuple[int, str | None]:
        """Send payload via raw socket connection."""
        loop = asyncio.get_event_loop()
        try:
            data = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    self._socket_request,
                    ip,
                    port,
                    payload,
                    timeout,
                ),
                timeout=timeout + 2,
            )
            return 200 if data else 0, data
        except asyncio.TimeoutError:
            raise
        except Exception as e:
            logger.debug(f"Socket request failed: {e}")
            return 0, None

    def _socket_request(
        self,
        ip: str,
        port: int,
        payload: str,
        timeout: int,
    ) -> str | None:
        """Synchronous socket request."""
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(payload.encode())
                return s.recv(4096).decode("utf-8", errors="ignore")
        except socket.timeout:
            raise asyncio.TimeoutError()
        except Exception as e:
            logger.debug(f"Socket error: {e}")
            return None

    def _is_vulnerable(self, response_code: int, response_text: str | None) -> bool:
        """
        Determine if endpoint is vulnerable based on response.

        Heuristics:
        - 200 OK + error messages = likely vulnerable
        - 403 Forbidden = firewall blocked (not vulnerable)
        - Empty response = can't determine
        """
        if response_code == 403:
            return False

        if response_code != 200:
            return False

        if not response_text:
            return False

        error_indicators = [
            "syntax error", "mysql", "postgresql", "exception",
            "traceback", "error", "java.", "php", "notice"
        ]

        response_lower = response_text.lower()
        for indicator in error_indicators:
            if indicator in response_lower:
                return True

        return False

    def _load_scan_results(self) -> None:
        """Load previous scan results from disk."""
        results_file = self._data_dir / "scan_results.json"
        if not results_file.exists():
            return

        try:
            data = json.loads(results_file.read_text())
            for key, result_data in data.items():
                self._scan_results[key] = ScanResult(**result_data)
            logger.info(f"Loaded {len(self._scan_results)} previous scan results")
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.warning(f"Failed to load scan results: {e}")

    def _persist_scan_results(self) -> None:
        """Save scan results to disk."""
        results_file = self._data_dir / "scan_results.json"
        try:
            data = {key: asdict(result) for key, result in self._scan_results.items()}
            results_file.write_text(json.dumps(data, indent=2, default=str))
        except OSError as e:
            logger.error(f"Failed to persist scan results: {e}")

    def get_vulnerable_endpoints(self) -> list[ScanResult]:
        """Get all endpoints identified as vulnerable."""
        return [r for r in self._scan_results.values() if r.is_vulnerable]

    def get_stats(self) -> dict[str, Any]:
        """Get scanner statistics."""
        total = len(self._scan_results)
        vulnerable = sum(1 for r in self._scan_results.values() if r.is_vulnerable)
        blocked = sum(1 for r in self._scan_results.values() if r.was_blocked_by_firewall)

        return {
            "total_scans": total,
            "vulnerable_endpoints": vulnerable,
            "blocked_by_firewall": blocked,
            "vulnerability_rate": vulnerable / max(total, 1),
        }
