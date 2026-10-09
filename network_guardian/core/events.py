# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Wolf-Pak Event Fabric — cross-app event bus with HTTP intake and SQLite storage.

This extends the in-process EventBus (used by the dashboard) with:
- A common event envelope (timestamp_ms, asset_id, source, event_type,
  severity, category, description, payload) that MASK and PakShield can
  POST to an intake endpoint.
- SQLite-backed append-only storage (EventStorage) for audited events.
- Subscription by event family so the Security Graph, Policy Engine, and
  AI Orchestrator can react to incoming events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

logger = logging.getLogger("network_guardian.core.events")

Callback = Callable[["Event"], Coroutine[Any, Any, None]]

# ---------------------------------------------------------------------------
# Existing lightweight bus (kept for in-process use by dashboard/agents)
# ---------------------------------------------------------------------------

@dataclass
class Event:
    """An event published on the in-process bus."""

    topic: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EventBus:
    """Simple async pub-sub event bus (in-process)."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callback]] = defaultdict(list)

    def subscribe(self, topic: str, callback: Callback) -> None:
        self._subscribers[topic].append(callback)

    def unsubscribe(self, topic: str, callback: Callback) -> None:
        self._subscribers[topic] = [
            cb for cb in self._subscribers[topic] if cb is not callback
        ]

    async def publish(self, event: Event) -> None:
        logger.debug("Event published: %s", event.topic)
        callbacks = self._subscribers.get(event.topic, [])
        for cb in callbacks:
            try:
                result = cb(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Error in event handler for %s", event.topic)


# ---------------------------------------------------------------------------
# Common cross-app event envelope (used by HTTP intake from MASK / PakShield)
# ---------------------------------------------------------------------------

# Valid severity values
SEVERITY_VALUES = frozenset({"info", "low", "medium", "high", "critical"})
# Valid category values
CATEGORY_VALUES = frozenset({
    "process", "network", "auth", "identity", "file", "device",
    "policy", "threat", "system", "other",
})


@dataclass
class CrossAppEnvelope:
    """The common event envelope that external apps (MASK, PakShield) POST.

    Fields:
        timestamp_ms:   Epoch milliseconds (UTC) when the observation was made.
        asset_id:       Stable asset identifier (see correlation spec §2.2).
        source:         Producing app: ``MASK``, ``PAKSHIELD``, ``NETWORK_GUARDIAN``, ``NSEP``.
        source_version: Optional producing app version.
        event_type:     Specific observation type (e.g. ``process_observation``).
        severity:       One of ``info``, ``low``, ``medium``, ``high``, ``critical``.
        category:       High-level taxonomy (process, network, auth, identity, etc.).
        description:    Human-readable summary.
        payload:        Structured data specific to the event type.
        tenant_id:      Optional tenant identifier for multi-tenant isolation.
    """

    timestamp_ms: int
    asset_id: str
    source: str
    source_version: str = ""
    event_type: str = ""
    severity: str = "info"
    category: str = "other"
    description: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    tenant_id: str = ""

    def to_event(self) -> Event:
        """Convert to an in-process Event for the internal bus."""
        return Event(
            topic=f"{self.source}:{self.event_type}",
            data={
                "envelope": self.to_dict(),
                "timestamp": datetime.fromtimestamp(
                    self.timestamp_ms / 1000.0, tz=timezone.utc
                ).isoformat(),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp_ms": self.timestamp_ms,
            "asset_id": self.asset_id,
            "source": self.source,
            "source_version": self.source_version,
            "event_type": self.event_type,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "payload": self.payload,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CrossAppEnvelope":
        return cls(
            timestamp_ms=int(d.get("timestamp_ms", 0)),
            asset_id=str(d.get("asset_id", "")),
            source=str(d.get("source", "")).upper(),
            source_version=str(d.get("source_version", "")),
            event_type=str(d.get("event_type", "")),
            severity=str(d.get("severity", "info")),
            category=str(d.get("category", "other")),
            description=str(d.get("description", "")),
            payload=json.loads(d["payload"]) if isinstance(d.get("payload"), str) else (d.get("payload") or {}),
            tenant_id=str(d.get("tenant_id", "")),
        )

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty = valid)."""
        errors = []
        if self.timestamp_ms <= 0:
            errors.append("timestamp_ms must be a positive epoch millisecond")
        if not self.asset_id:
            errors.append("asset_id is required")
        if self.source not in {"MASK", "PAKSHIELD", "NETWORK_GUARDIAN", "NSEP", ""}:
            errors.append(
                f"source must be MASK, PAKSHIELD, NETWORK_GUARDIAN, or NSEP; got {self.source!r}"
            )
        if self.severity not in SEVERITY_VALUES:
            errors.append(
                f"severity must be one of {sorted(SEVERITY_VALUES)}; got {self.severity!r}"
            )
        if self.category not in CATEGORY_VALUES:
            errors.append(
                f"category must be one of {sorted(CATEGORY_VALUES)}; got {self.category!r}"
            )
        if not isinstance(self.payload, dict):
            errors.append("payload must be a JSON object")
        return errors


# ---------------------------------------------------------------------------
# SQLite-backed append-only event storage
# ---------------------------------------------------------------------------

class EventStorage:
    """Append-only, queryable store for cross-app event envelopes.

    Persists envelopes to a SQLite database for later retrieval, replay,
    and compliance reporting.
    """

    def __init__(self, db_path: str = "wolfpak_events.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS envelopes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms INTEGER NOT NULL,
                asset_id    TEXT    NOT NULL,
                source      TEXT    NOT NULL,
                source_version TEXT,
                event_type  TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                category    TEXT    NOT NULL,
                description TEXT,
                payload     TEXT    NOT NULL DEFAULT '{}',
                tenant_id   TEXT,
                stored_at   TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_envelopes_asset
                ON envelopes (asset_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_envelopes_source
                ON envelopes (source)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_envelopes_type
                ON envelopes (event_type)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_envelopes_stored
                ON envelopes (stored_at)
            """
        )
        conn.commit()
        conn.close()

    def store(self, envelope: CrossAppEnvelope) -> int:
        """Append an envelope and return the row id."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute(
            """
            INSERT INTO envelopes
                (timestamp_ms, asset_id, source, source_version,
                 event_type, severity, category, description,
                 payload, tenant_id, stored_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                envelope.timestamp_ms,
                envelope.asset_id,
                envelope.source,
                envelope.source_version,
                envelope.event_type,
                envelope.severity,
                envelope.category,
                envelope.description,
                json.dumps(envelope.payload),
                envelope.tenant_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        row_id = cur.lastrowid
        conn.commit()
        conn.close()
        logger.debug("Stored envelope id=%d asset=%s source=%s type=%s",
                     row_id, envelope.asset_id, envelope.source, envelope.event_type)
        return row_id

    def query(
        self,
        *,
        source: str = "",
        event_type: str = "",
        asset_id: str = "",
        severity: str = "",
        since_ms: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve stored envelopes matching the given filters."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conditions: list[str] = []
        params: list[Any] = []
        if source:
            conditions.append("source = ?")
            params.append(source)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if asset_id:
            conditions.append("asset_id = ?")
            params.append(asset_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if since_ms:
            conditions.append("timestamp_ms >= ?")
            params.append(since_ms)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            f"SELECT * FROM envelopes {where} ORDER BY stored_at DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def query_by_asset(self, asset_id: str, limit: int = 200) -> list[dict[str, Any]]:
        """Get all events for a specific asset (for graph / investigation)."""
        return self.query(asset_id=asset_id, limit=limit)

    def clear(self) -> int:
        """Drop all stored envelopes. Returns count of deleted rows."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("DELETE FROM envelopes")
        count = cur.rowcount
        conn.commit()
        conn.close()
        return count


# ---------------------------------------------------------------------------
# Global singletons (shared across the process)
# ---------------------------------------------------------------------------

_bus = EventBus()
_storage: EventStorage | None = None


def get_event_bus() -> EventBus:
    """Return the shared in-process event bus."""
    return _bus


def get_event_storage() -> EventStorage:
    """Return the shared SQLite event storage (lazy-initialised)."""
    global _storage
    if _storage is None:
        _storage = EventStorage()
    return _storage


async def publish_envelope(envelope: CrossAppEnvelope) -> int:
    """Store an envelope and publish it on the internal bus.

    Returns the storage row id.
    """
    storage = get_event_storage()
    row_id = storage.store(envelope)
    event = envelope.to_event()
    await _bus.publish(event)
    return row_id
