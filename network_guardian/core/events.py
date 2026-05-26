# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Lightweight publish-subscribe event bus.

Subsystems communicate through events to stay decoupled.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

logger = logging.getLogger("network_guardian.core.events")

Callback = Callable[["Event"], Coroutine[Any, Any, None]]


@dataclass
class Event:
    """An event published on the bus."""

    topic: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EventBus:
    """Simple async pub-sub event bus."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callback]] = defaultdict(list)

    def subscribe(self, topic: str, callback: Callback) -> None:
        """Register a callback for a topic."""
        self._subscribers[topic].append(callback)

    def unsubscribe(self, topic: str, callback: Callback) -> None:
        """Remove a callback from a topic."""
        self._subscribers[topic] = [
            cb for cb in self._subscribers[topic] if cb is not callback
        ]

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribers of its topic."""
        logger.debug("Event published: %s", event.topic)
        callbacks = self._subscribers.get(event.topic, [])
        for cb in callbacks:
            try:
                result = cb(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Error in event handler for %s", event.topic)
