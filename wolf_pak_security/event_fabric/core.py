"""Event Fabric core — public API for the event bus.


This module exposes the primitives modules use to publish and
subscribe to events flowing through the Wolf-Pak Event Fabric.
"""

from __future__ import annotations

from typing import Any, Callable


class EventEnvelope:
    """A typed wrapper around any Wolf-Pak event.

    The envelope carries the raw event plus minimal routing metadata
    so the fabric can deliver it to the right subscribers.
    """

    def __init__(self, *, family: str, payload: Any, source: str) -> None:
        """Initialise an envelope.

        Args:
            family: Event family name — ``detection``, ``intel``, or ``audit``.
            payload: The event dataclass instance.
            source: Name of the producing module.
        """
        self.family = family
        self.payload = payload
        self.source = source


class EventBus:
    """In-process, in-memory event bus for the Event Fabric.

    Publish-subscribe semantics: publishers emit event envelopes and
    subscribers register callbacks filtered by event family.
    """

    def subscribe(self, *, family: str, callback: Callable[[EventEnvelope], None]) -> None:
        """Register a callback for an event family.

        Args:
            family: Event family to listen for.
            callback: Callable receiving an EventEnvelope.
        """
        pass

    def unsubscribe(self, *, family: str, callback: Callable[[EventEnvelope], None]) -> None:
        """Remove a previously registered callback.

        Args:
            family: Event family the callback was subscribed to.
            callback: The exact callable to remove.
        """
        pass

    def publish(self, *, envelope: EventEnvelope) -> None:
        """Emit an event envelope to all matching subscribers.

        Args:
            envelope: The event to publish.
        """
        pass


class EventStorage:
    """Append-only, queryable store for audited events.

    Persists event envelopes for later retrieval, replay, and
    compliance reporting.  Backing implementation is pluggable.
    """

    def store(self, *, envelope: EventEnvelope) -> None:
        """Append an envelope to the store.

        Args:
            envelope: The event envelope to persist.
        """
        pass

    def query(self, *, family: str, since: str = "", limit: int = 100) -> list[EventEnvelope]:
        """Retrieve stored envelopes filtered by family.

        Args:
            family: Event family to filter on.
            since: ISO-8601 timestamp cursor (inclusive).
            limit: Maximum number of envelopes to return.

        Returns:
            List of matching EventEnvelope instances.
        """
        pass
