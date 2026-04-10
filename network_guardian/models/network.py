"""Shared data models for network hosts, findings, and metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HostStatus(Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


@dataclass
class Host:
    """Represents a network host."""

    ip: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    status: HostStatus = HostStatus.UNKNOWN
    open_ports: list[int] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Finding:
    """An audit finding (vulnerability, misconfiguration, etc.)."""

    title: str
    description: str
    severity: Severity = Severity.INFO
    host: str | None = None
    port: int | None = None
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Metric:
    """A single metric data point for monitoring."""

    name: str
    value: float
    unit: str = ""
    host: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
