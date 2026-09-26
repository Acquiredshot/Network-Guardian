"""Threat Intel core — public API for indicator and intelligence management.


This module exposes the interfaces for ingesting threat intelligence
from feeds, normalising it, and serving indicators to other modules.
"""

from __future__ import annotations

from typing import Any


class IntelIngestor:
    """Pull / receive intelligence from a single source.

    Each ingestor is tied to one feed or source and is responsible for
    fetching, parsing, and normalising raw intelligence into IntelEvent
    records.
    """

    def ingest(self, *, since: str | None = None) -> list[dict[str, Any]]:
        """Pull intelligence records from the source.

        Args:
            since: Optional ISO-8601 cursor for incremental ingestion.

        Returns:
            List of normalised intelligence dicts.
        """
        pass

    def source_name(self) -> str:
        """Return the human-readable name of this intel source.

        Returns:
            Source name string.
        """
        pass


class IntelStore:
    """Persistence and lookup for intelligence records.

    Holds a deduplicated, queryable set of IntelEvents keyed by
    indicator and intel id.
    """

    def add(self, *, intel: dict[str, Any]) -> None:
        """Persist an intelligence record.

        Args:
            intel: Normalised intelligence dict to store.
        """
        pass

    def lookup(self, *, indicator: str) -> list[dict[str, Any]]:
        """Find intelligence records matching an observable.

        Args:
            indicator: The observable to look up (hash, domain, IP, etc.).

        Returns:
            List of matching intelligence dicts.
        """
        pass

    def query(
        self,
        *,
        intel_type: str | None = None,
        confidence_min: float = 0.0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query stored intelligence with optional filters.

        Args:
            intel_type: Filter by intelligence category.
            confidence_min: Minimum confidence threshold.
            limit: Maximum records to return.

        Returns:
            List of matching intelligence dicts.
        """
        pass


class IntelEnricher:
    """Attach intelligence context to other event types.

    Takes a raw observable or event and enriches it with matching
    intelligence records sourced from the IntelStore.
    """

    def enrich(self, *, observable: str, observable_type: str) -> dict[str, Any]:
        """Enrich a single observable with threat intelligence.

        Args:
            observable: The value to enrich (hash, domain, IP, etc.).
            observable_type: Type of the observable.

        Returns:
            Enriched dict with intelligence context attached.
        """
        pass
