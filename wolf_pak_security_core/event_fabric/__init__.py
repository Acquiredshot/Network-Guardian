# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Wolf-Pak Security Core — Event Fabric.

Central event bus that ingests events from all three platform pillars
(Network Guardian, Pakshield, Mask Network), normalizes them, and routes
them to Security Graph, Threat Intel, and the AI Security Orchestrator.

Event flow:
    producers (NG + Pakshield + Mask) ──► EventFabric.normalize()
                                                │
                                   ┌───────────┼───────────┐
                                   ▼           ▼           ▼
                              SecurityGraph  ThreatIntel  AI Orchestrator
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class EventCategory(Enum):
    THREAT = "threat"
    IDENTITY = "identity"
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    SYSTEM = "system"
    ACTION = "action"
    POLICY = "policy"


@dataclass
class SecurityEvent:
    """Normalized security event from any platform pillar."""

    event_id: str
    timestamp: float
    source: str  # "network_guardian", "pakshield", "mask_network"
    category: EventCategory
    severity: str  # "info", "low", "medium", "high", "critical"
    title: str
    detail: dict[str, Any] = field(default_factory=dict)
    entity_ids: list[str] = field(default_factory=list)  # asset/identity/graph ids
    raw: dict[str, Any] = field(default_factory=dict)  # original event payload

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "category": self.category.value,
            "severity": self.severity,
            "title": self.title,
            "entity_count": len(self.entity_ids),
        }


class EventFabric:
    """Phase 1 event fabric — ingestion, normalization, fan-out via asyncio.Queue."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[SecurityEvent] = asyncio.Queue()
        self._handlers: dict[EventCategory, list[Callable[[SecurityEvent], Any]]] = {}
        self._events: list[SecurityEvent] = []
        self._counter = 0

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, event: dict[str, Any], source: str = "unknown") -> SecurityEvent:
        """Normalize and enqueue a raw event from a platform pillar."""
        normalized = self._normalize(event, source)
        self._queue.put_nowait(normalized)
        self._events.append(normalized)
        self._fan_out(normalized)
        return normalized

    async def run_drain(self, timeout: float = 30.0) -> list[SecurityEvent]:
        """Drain pending events from the queue (async consumer)."""
        collected: list[SecurityEvent] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                event = self._queue.get_nowait()
                collected.append(event)
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.05)
        return collected

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def register_handler(
        self, category: EventCategory, handler: Callable[[SecurityEvent], Any]
    ) -> None:
        """Register a handler for a specific event category."""
        self._handlers.setdefault(category, []).append(handler)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _normalize(self, raw: dict[str, Any], source: str) -> SecurityEvent:
        category_str = str(raw.get("category", raw.get("type", "system")))
        try:
            category = EventCategory(category_str)
        except ValueError:
            category = EventCategory.SYSTEM

        severity = str(raw.get("severity", raw.get("level", "info"))).lower()
        if severity not in ("info", "low", "medium", "high", "critical"):
            severity = "info"

        entity_ids = raw.get("entity_ids", raw.get("entities", []))
        if isinstance(entity_ids, str):
            entity_ids = [entity_ids]

        return SecurityEvent(
            event_id=f"evt-{int(time.time() * 1000)}-{self._counter}",
            timestamp=float(raw.get("timestamp", time.time())),
            source=source,
            category=category,
            severity=severity,
            title=str(raw.get("title", raw.get("message", "Untitled event"))),
            detail=raw.get("detail", raw),
            entity_ids=entity_ids,
            raw={k: v for k, v in raw.items() if k not in ("category", "type", "severity", "level", "title", "message", "entity_ids", "entities", "detail")},
        )

    def _fan_out(self, event: SecurityEvent) -> None:
        """Deliver event to registered handlers."""
        for handler in self._handlers.get(event.category, []):
            try:
                handler(event)
            except Exception:
                pass
