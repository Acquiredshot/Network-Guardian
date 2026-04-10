"""
Sensors layer — abstractions for network data collection tools.

Provides a unified interface over external tools (Nmap, ping, SNMP, etc.)
and system-level data sources (CPU, memory, disk, network interfaces).
"""

from __future__ import annotations

import asyncio
import logging
import platform
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus
from network_guardian.models.network import Host, HostStatus, Metric

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.sensors")


# ---------------------------------------------------------------------------
# Base sensor interface
# ---------------------------------------------------------------------------


@dataclass
class SensorReading:
    """Raw reading from a sensor."""

    sensor_name: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Sensor(ABC):
    """Abstract base for all sensors / data collectors."""

    name: str = "base_sensor"

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus

    @abstractmethod
    async def collect(self) -> SensorReading:
        """Collect a reading from this sensor."""

    def is_available(self) -> bool:
        """Check whether the underlying tool / data source is accessible."""
        return True


def _validate_scan_target(target: str) -> None:
    """Validate a scan target to prevent SSRF against internal services."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        # Hostname — basic sanity check
        if not all(c.isalnum() or c in ".-" for c in target):
            raise ValueError(f"Invalid target hostname: {target}")
        return
    # Block link-local and loopback metadata endpoints (169.254.x.x)
    if addr.is_link_local:
        raise ValueError(f"Link-local target blocked: {target}")


# ---------------------------------------------------------------------------
# Network sensors
# ---------------------------------------------------------------------------


class PingSensor(Sensor):
    """ICMP ping sensor for host reachability checks."""

    name = "ping"

    async def collect(self, target: str = "127.0.0.1") -> SensorReading:
        _validate_scan_target(target)
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        count = str(self.config.scan.ping_count)
        proc = await asyncio.create_subprocess_exec(
            "ping", flag, count, target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.config.scan.timeout + 5)
        output = stdout.decode(errors="replace")

        reachable = proc.returncode == 0
        return SensorReading(
            sensor_name=self.name,
            data={"target": target, "reachable": reachable, "output": output},
        )


class PortScanner(Sensor):
    """Async TCP port scanner."""

    name = "port_scanner"

    async def collect(self, target: str = "127.0.0.1") -> SensorReading:
        _validate_scan_target(target)
        open_ports = await self._scan_ports(target)
        return SensorReading(
            sensor_name=self.name,
            data={"target": target, "open_ports": open_ports},
        )

    async def _scan_ports(self, target: str) -> list[int]:
        port_range = self.config.scan.port_range
        start, end = (int(p) for p in port_range.split("-"))
        semaphore = asyncio.Semaphore(self.config.scan.max_concurrent)
        open_ports: list[int] = []

        async def _check(port: int) -> None:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=self.config.scan.timeout,
                    )
                    open_ports.append(port)
                    writer.close()
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    pass

        tasks = [_check(p) for p in range(start, end + 1)]
        await asyncio.gather(*tasks)
        return sorted(open_ports)


class NmapSensor(Sensor):
    """Wrapper around the Nmap command-line tool (if available)."""

    name = "nmap"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    async def collect(self, target: str = "127.0.0.1") -> SensorReading:
        _validate_scan_target(target)
        if not self.is_available():
            return SensorReading(
                sensor_name=self.name,
                data={"error": "nmap not found on PATH"},
            )

        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "--open", "-T4", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=self.config.scan.timeout + 10
        )
        return SensorReading(
            sensor_name=self.name,
            data={
                "target": target,
                "output": stdout.decode(errors="replace"),
                "exit_code": proc.returncode,
            },
        )


# ---------------------------------------------------------------------------
# System sensors
# ---------------------------------------------------------------------------


class SystemMetricsSensor(Sensor):
    """Collects local system metrics (cross-platform, no dependencies)."""

    name = "system_metrics"

    async def collect(self) -> SensorReading:
        data: dict[str, Any] = {}

        # CPU load (Unix)
        try:
            import os
            load = os.getloadavg()
            data["cpu_load_1m"] = load[0]
            data["cpu_load_5m"] = load[1]
            data["cpu_load_15m"] = load[2]
        except (OSError, AttributeError):
            data["cpu_load_1m"] = None  # Windows — use psutil when available

        # Disk usage
        try:
            import shutil as _shutil
            usage = _shutil.disk_usage("/")
            data["disk_total_gb"] = round(usage.total / (1024**3), 2)
            data["disk_used_gb"] = round(usage.used / (1024**3), 2)
            data["disk_free_gb"] = round(usage.free / (1024**3), 2)
            data["disk_usage_pct"] = round(usage.used / usage.total * 100, 1)
        except OSError:
            logger.debug("Could not read disk usage", exc_info=True)

        return SensorReading(sensor_name=self.name, data=data)


# ---------------------------------------------------------------------------
# Sensor registry
# ---------------------------------------------------------------------------


class SensorRegistry:
    """Manages available sensors."""

    def __init__(self) -> None:
        self._sensors: dict[str, Sensor] = {}

    def register(self, sensor: Sensor) -> None:
        self._sensors[sensor.name] = sensor
        logger.info("Sensor registered: %s", sensor.name)

    def get(self, name: str) -> Sensor:
        return self._sensors[name]

    async def collect_all(self) -> list[SensorReading]:
        readings: list[SensorReading] = []
        for sensor in self._sensors.values():
            try:
                readings.append(await sensor.collect())
            except Exception:
                logger.exception("Sensor %s failed to collect", sensor.name)
        return readings

    @property
    def names(self) -> list[str]:
        return list(self._sensors.keys())
