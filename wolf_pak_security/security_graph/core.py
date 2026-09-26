"""Security Graph core — public API for graph operations.


This module exposes the graph model, ingestion, and query primitives
that let other Wolf-Pak modules correlate entities and investigate
attack paths.
"""

from __future__ import annotations

from typing import Any


class GraphEntity:
    """A node in the security graph.

    Represents a real-world or logical security-relevant thing:
    a host, user, process, file, or network endpoint.
    """

    def __init__(self, *, entity_id: str, entity_type: str, properties: dict[str, Any] | None = None) -> None:
        """Initialise an entity.

        Args:
            entity_id: Stable identifier for this entity.
            entity_type: Category — ``host``, ``user``, ``process``,
                ``file``, ``network_endpoint``, etc.
            properties: Arbitrary key-value attributes attached to the entity.
        """
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.properties = properties or {}

    def update(self, *, properties: dict[str, Any]) -> None:
        """Merge new properties into the entity.

        Args:
            properties: Dict of properties to merge (shallow).
        """
        pass

    def to_dict(self) -> dict[str, Any]:
        """Serialise the entity to a plain dict.

        Returns:
            A dict representation suitable for storage or serialisation.
        """
        pass


class GraphRelationship:
    """An edge connecting two GraphEntity nodes.

    Captures how two entities relate — ``ran_on``, ``accessed``,
    ``communicated_with``, ``created``, etc.
    """

    def __init__(
        self,
        *,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Initialise a relationship.

        Args:
            source_id: Entity id of the source node.
            target_id: Entity id of the target node.
            relationship_type: Edge type label.
            properties: Optional edge attributes (timestamp, confidence, etc.).
        """
        self.source_id = source_id
        self.target_id = target_id
        self.relationship_type = relationship_type
        self.properties = properties or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialise the relationship to a plain dict.

        Returns:
            A dict representation suitable for storage or serialisation.
        """
        pass


class SecurityGraph:
    """The central graph store and query surface.

    Maintains the live set of entities and relationships, ingests
    detection events to keep the graph current, and supports
    neighbourhood and path queries for investigation.
    """

    def upsert_entity(self, *, entity: GraphEntity) -> None:
        """Insert or update an entity in the graph.

        Args:
            entity: The entity to upsert.
        """
        pass

    def upsert_relationship(self, *, relationship: GraphRelationship) -> None:
        """Insert or update a relationship edge.

        Args:
            relationship: The relationship to upsert.
        """
        pass

    def ingest_detection(self, *, event: dict[str, Any]) -> None:
        """Update the graph from a detection event payload.

        Args:
            event: Deserialised detection event dict.
        """
        pass

    def neighbours(self, *, entity_id: str, relationship_type: str | None = None) -> list[GraphEntity]:
        """Return entities connected to the given entity.

        Args:
            entity_id: The centre entity.
            relationship_type: Optional edge-type filter.

        Returns:
            List of neighbouring GraphEntity instances.
        """
        pass

    def shortest_path(self, *, source_id: str, target_id: str) -> list[GraphRelationship] | None:
        """Find the shortest relationship path between two entities.

        Args:
            source_id: Starting entity id.
            target_id: Destination entity id.

        Returns:
            List of GraphRelationships on the path, or ``None`` if no path exists.
        """
        pass

    def query(self, *, entity_type: str, property_filter: dict[str, Any] | None = None) -> list[GraphEntity]:
        """Query entities by type and optional property predicate.

        Args:
            entity_type: Entity type to match.
            property_filter: Optional dict of property key-value pairs to match.

        Returns:
            List of matching GraphEntity instances.
        """
        pass
