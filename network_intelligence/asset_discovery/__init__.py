# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Mask Network — Network/Asset Intelligence pillar.

Asset Discovery — active + passive discovery, service fingerprinting.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AssetType(Enum):
    Hosts = "host"
    Service = "service"
    Network = "network"
    Cloud = "cloud"
    Unknown = "unknown"


@dataclass
class Asset:
    """A single discovered asset."""

    id: str
    type: AssetType
    address: str  # IP or hostname
    name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    confidence: float = 1.0  # 0..1

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "address": self.address,
            "name": self.name,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "metadata_count": len(self.metadata),
        }


class AssetDiscovery:
    """Phase 1 asset discovery — subnet sweep + single-host probe."""

    def __init__(self, timeout: float = 2.0, max_concurrent: int = 50) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._assets: dict[str, Asset] = {}
        self._session: Any | None = None

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover_subnet(self, cidr: str) -> list[Asset]:
        """Discover live hosts in a CIDR block via TCP SYN to port 80/443."""
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(host) for host in network.hosts()]
        if not hosts:
            # /31 or /32 edge case
            hosts = [str(network.network_address)]

        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._probe(host, semaphore) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        assets: list[Asset] = []
        now = time.time()
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            if result is not None:
                result.first_seen = now
                result.last_seen = now
                assets.append(result)
                self._assets[result.id] = result

        return assets

    async def probe_host(self, address: str, ports: list[int] | None = None) -> Asset:
        """Single-host probe with optional port list."""
        if ports is None:
            ports = [80, 443, 22, 8080, 8443]
        semaphore = asyncio.Semaphore(1)
        return await self._probe(address, semaphore, ports=ports)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _probe(
        self, address: str, semaphore: asyncio.Semaphore, ports: list[int] | None = None
    ) -> Asset | None:
        if ports is None:
            ports = [80, 443]

        async with semaphore:
            open_ports: list[int] = []
            for port in ports:
                if await self._tcp_check(address, port):
                    open_ports.append(port)

            if not open_ports:
                # Still record the host if we got any response (e.g. ICMP)
                # Phase 1: require at least one open port for host asset.
                return None

            svc_names = _service_names_for_ports(open_ports)
            svc_str = ", ".join(svc_names) if svc_names else "unknown"

            return Asset(
                id=f"asset-{address.replace('.', '-')}",
                type=AssetType.Hosts,
                address=address,
                name=f"Host ({svc_str})",
                metadata={"open_ports": open_ports, "services": svc_names},
                confidence=0.85,
            )

    async def _tcp_check(self, host: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SERVICE_MAP = {
    22: "ssh",
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
}


def _service_names_for_ports(ports: list[int]) -> list[str]:
    return [_SERVICE_MAP.get(p, f"port-{p}") for p in ports]
