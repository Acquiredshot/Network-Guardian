# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""Wolf-Pak Security Graph — in-memory graph for correlating entities
across Network Guardian, MASK, and PakShield.

Maintains nodes (hosts, devices, identities, processes, network flows,
policies, threat indicators) and edges (host_has_process, flows_between,
identity_uses_device, etc.). Ingests cross-app event envelopes to keep
the graph current and supports neighbourhood / path queries for
investigation.

Exports:
    SecurityGraph     — the graph object (ingest, query, neighbourhood, stats)
    GRAPH_ENTITY_TYPES — frozenset of valid entity type strings
    GRAPH_EDGE_TYPES   — frozenset of valid relationship type strings
"""

from __future__ import annotations

import logging
from typing import Any

from network_guardian.core.events import CrossAppEnvelope, SEVERITY_VALUES

logger = logging.getLogger("network_guardian.core.security_graph")


# ---------------------------------------------------------------------------
# Node and edge types
# ---------------------------------------------------------------------------

ENTITY_TYPES = frozenset({
    "host", "device", "identity", "process", "network_flow",
    "policy", "threat_indicator", "credential", "session", "application",
})

RELATIONSHIP_TYPES: frozenset[str] = frozenset({
    "host_has_process", "host_has_session", "host_has_listener",
    "flows_between", "flow_involves_host",
    "identity_uses_device", "identity_has_role",
    "device_has_policy", "identity_has_risk",
    "process_created_by", "process_communicates_with",
})

GRAPH_ENTITY_TYPES: frozenset[str] = ENTITY_TYPES
GRAPH_EDGE_TYPES: frozenset[str] = RELATIONSHIP_TYPES


class GraphEntity:
    """A node in the security graph."""

    def __init__(
        self,
        *,
        entity_id: str,
        entity_type: str,
        properties: dict[str, Any] | None = None,
        source: str = "",
        first_seen_ms: int = 0,
        last_seen_ms: int = 0,
    ) -> None:
        if entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"entity_type must be one of {sorted(ENTITY_TYPES)}; got {entity_type!r}"
            )
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.properties = properties or {}
        self.source = source
        self.first_seen_ms = first_seen_ms or 0
        self.last_seen_ms = last_seen_ms or 0
        self._native_refs: dict[str, str] = {}  # source -> native id

    def update(self, *, properties: dict[str, Any], source: str = "", last_seen_ms: int = 0) -> None:
        self.properties.update(properties)
        if source:
            self.source = source
        if last_seen_ms:
            self.last_seen_ms = max(self.last_seen_ms, last_seen_ms)

    def add_native_ref(self, source: str, native_id: str) -> None:
        """Record the native ID from another app for this entity."""
        self._native_refs[source] = native_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "properties": dict(self.properties),
            "source": self.source,
            "first_seen_ms": self.first_seen_ms,
            "last_seen_ms": self.last_seen_ms,
            "native_refs": dict(self._native_refs),
        }


class GraphRelationship:
    """An edge connecting two GraphEntity nodes."""

    def __init__(
        self,
        *,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        if relationship_type not in RELATIONSHIP_TYPES:
            # Allow new relationship types; just log a warning later
            pass
        self.source_id = source_id
        self.target_id = target_id
        self.relationship_type = relationship_type
        self.properties = properties or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type,
            "properties": dict(self.properties),
        }


# ---------------------------------------------------------------------------
# Security Graph
# ---------------------------------------------------------------------------

class SecurityGraph:
    """Central graph store for correlating entities across the Wolf-Pak stack.

    Ingests cross-app event envelopes, maintains entities and relationships,
    and supports neighbourhood and path queries for investigation.
    """

    def __init__(self) -> None:
        self._entities: dict[str, GraphEntity] = {}
        self._relationships: dict[str, GraphRelationship] = {}
        self._rel_index: dict[tuple[str, str], list[str]] = {}  # (src,reltype) -> [rel_id,...]
        self._ingest_count = 0
        self._entity_count = 0
        self._rel_count = 0

    # -- entity management --

    def upsert_entity(self, *, entity: GraphEntity) -> GraphEntity:
        existing = self._entities.get(entity.entity_id)
        if existing:
            existing.update(
                properties=entity.properties,
                source=entity.source or existing.source,
                last_seen_ms=entity.last_seen_ms or existing.last_seen_ms,
            )
            if entity._native_refs:
                existing._native_refs.update(entity._native_refs)
            return existing
        self._entities[entity.entity_id] = entity
        self._entity_count += 1
        return entity

    def get_entity(self, entity_id: str) -> GraphEntity | None:
        return self._entities.get(entity_id)

    def query(self, *, entity_type: str, property_filter: dict[str, Any] | None = None) -> list[GraphEntity]:
        """Return entities matching type and optional property predicate."""
        results: list[GraphEntity] = []
        for ent in self._entities.values():
            if ent.entity_type != entity_type:
                continue
            if property_filter:
                match = True
                for k, v in property_filter.items():
                    if ent.properties.get(k) != v:
                        match = False
                        break
                if not match:
                    continue
            results.append(ent)
        return results

    def get_by_asset_id(self, asset_id: str) -> GraphEntity | None:
        """Convenience: look up an entity by its asset_id (which is the entity_id)."""
        return self._entities.get(asset_id)

    # -- relationship management --

    def upsert_relationship(self, *, relationship: GraphRelationship) -> GraphRelationship:
        rel_id = self._rel_id(relationship.source_id, relationship.relationship_type, relationship.target_id)
        existing = self._relationships.get(rel_id)
        if existing:
            existing.properties.update(relationship.properties)
            return existing
        self._relationships[rel_id] = relationship
        key = (relationship.source_id, relationship.relationship_type)
        self._rel_index.setdefault(key, []).append(rel_id)
        self._rel_count += 1
        return relationship

    def get_relationships(self, source_id: str, relationship_type: str | None = None) -> list[GraphRelationship]:
        """Return relationships originating from source_id, optionally filtered by type."""
        results: list[GraphRelationship] = []
        for rel in self._relationships.values():
            if rel.source_id != source_id:
                continue
            if relationship_type and rel.relationship_type != relationship_type:
                continue
            results.append(rel)
        return results

    def neighbours(self, *, entity_id: str, relationship_type: str | None = None) -> list[GraphEntity]:
        """Return entities connected to the given entity (outgoing edges)."""
        results: list[GraphEntity] = []
        for rel in self.get_relationships(entity_id, relationship_type):
            target = self._entities.get(rel.target_id)
            if target:
                results.append(target)
        return results

    def _rel_id(self, src: str, rel_type: str, tgt: str) -> str:
        return f"{src}::{rel_type}::{tgt}"

    # -- ingestion from cross-app envelopes --

    def ingest_detection(self, *, envelope: CrossAppEnvelope) -> list[str]:
        """Update the graph from a cross-app event envelope.

        Returns list of entity_ids that were created or updated.
        """
        return self._ingest(envelope=envelope)

    def ingest(self, envelope: CrossAppEnvelope) -> list[str]:
        """Ingest a cross-app event envelope (used by dashboard intake handler)."""
        return self._ingest(envelope=envelope)

    def _ingest(self, *, envelope: CrossAppEnvelope) -> list[str]:
        touched: list[str] = []
        asset_id = envelope.asset_id
        src = envelope.source

        # Ensure the asset node exists
        entity = self._entities.get(asset_id)
        if entity is None:
            entity = GraphEntity(
                entity_id=asset_id,
                entity_type=self._asset_type_from_category(envelope.category),
                source=src,
                first_seen_ms=envelope.timestamp_ms,
                last_seen_ms=envelope.timestamp_ms,
            )
            self.upsert_entity(entity=entity)
            touched.append(asset_id)
            logger.info("Graph: created entity %s (type=%s, source=%s)",
                        asset_id, entity.entity_type, src)
        else:
            entity.update(
                properties=self._properties_from_payload(envelope),
                source=src,
                last_seen_ms=envelope.timestamp_ms,
            )
            entity.add_native_ref(src, envelope.payload.get("native_id", ""))
            touched.append(asset_id)

        # Create relationships based on event type and payload
        edges = self._edges_from_envelope(envelope, asset_id)
        for edge in edges:
            rel_key = self._rel_id(edge.source_id, edge.relationship_type, edge.target_id)
            if rel_key not in self._relationships:
                if edge.target_id not in self._entities:
                    tgt = GraphEntity(
                        entity_id=edge.target_id,
                        entity_type=self._guess_target_type(edge.relationship_type),
                        source=src,
                        first_seen_ms=envelope.timestamp_ms,
                        last_seen_ms=envelope.timestamp_ms,
                    )
                    self.upsert_entity(entity=tgt)
                self.upsert_relationship(relationship=edge)
                touched.append(edge.target_id)
            touched.append(edge.target_id)

        self._ingest_count += 1
        return touched

    def _asset_type_from_category(self, category: str) -> str:
        mapping = {
            "process": "process",
            "network": "network_flow",
            "auth": "identity",
            "identity": "identity",
            "device": "device",
            "file": "file",
            "policy": "policy",
            "threat": "threat_indicator",
            "system": "host",
            "other": "host",
        }
        return mapping.get(category, "host")

    def _guess_target_type(self, rel_type: str) -> str:
        mapping = {
            "host_has_process": "process",
            "host_has_session": "identity",
            "host_has_listener": "network_flow",
            "flows_between": "network_flow",
            "flow_involves_host": "host",
            "identity_uses_device": "device",
            "identity_has_role": "identity",
            "device_has_policy": "policy",
            "identity_has_risk": "identity",
            "process_created_by": "identity",
            "process_communicates_with": "process",
        }
        return mapping.get(rel_type, "host")

    def _properties_from_payload(self, envelope: CrossAppEnvelope) -> dict[str, Any]:
        p = dict(envelope.payload)
        p["description"] = envelope.description
        p["severity"] = envelope.severity
        p["event_type"] = envelope.event_type
        p["source"] = envelope.source
        return p

    def _edges_from_envelope(self, envelope: CrossAppEnvelope, asset_id: str) -> list[GraphRelationship]:
        """Derive edges from an envelope. Override or extend for specific event types."""
        edges: list[GraphRelationship] = []
        p = envelope.payload
        etype = envelope.event_type
        category = envelope.category

        if category == "network" and etype in {"network_flow_observation", "network_connection_observation"}:
            # A network flow observation: asset is the source host, create flow node
            dst = p.get("remote_address", p.get("dst_ip", ""))
            if dst:
                flow_id = f"flow-{asset_id}->{dst}"
                edges.append(GraphRelationship(
                    source_id=asset_id,
                    target_id=flow_id,
                    relationship_type="flows_between",
                    properties={
                        "dst": dst,
                        "port": p.get("remote_port", p.get("dst_port", 0)),
                        "protocol": p.get("protocol", "unknown"),
                        "state": p.get("state", ""),
                        "timestamp_ms": envelope.timestamp_ms,
                    },
                ))
                # Also link flow back to the destination host if we know it
                # (the destination host may be an asset we know about)
                # Don't create flow_involves_host for the source (asset_id) since
                # flows_between already captures src->flow
                if envelope.severity in {"high", "critical"}:
                    edges.append(GraphRelationship(
                        source_id=flow_id,
                        target_id=asset_id,
                        relationship_type="flow_involves_host",
                        properties={"role": "source", "timestamp_ms": envelope.timestamp_ms},
                    ))

        elif category == "process" and etype in {"process_observation", "process_list"}:
            # A process observation on a host: asset is the host, create process nodes
            processes = p.get("processes")
            if isinstance(processes, list):
                for proc in processes:
                    pid = str(proc.get("pid", proc.get("PID", "")))
                    if not pid:
                        continue
                    proc_id = f"proc-{asset_id}-{pid}"
                    edges.append(GraphRelationship(
                        source_id=asset_id,
                        target_id=proc_id,
                        relationship_type="host_has_process",
                        properties={
                            "pid": pid,
                            "name": proc.get("name", proc.get("comm", "")),
                            "user": proc.get("user", proc.get("USER", "")),
                            "cmdline": proc.get("cmdline", proc.get("args", "")),
                            "timestamp_ms": envelope.timestamp_ms,
                        },
                    ))

        elif category == "auth" and etype in {"user_session_observation", "user_sessions"}:
            # User sessions on a host: asset is the host, create identity nodes
            sessions = p.get("sessions")
            if isinstance(sessions, list):
                for sess in sessions:
                    user = str(sess.get("user", sess.get("USER", "")))
                    if not user:
                        continue
                    identity_id = f"identity-{envelope.source.lower()}-{user.lower()}"
                    edges.append(GraphRelationship(
                        source_id=asset_id,
                        target_id=identity_id,
                        relationship_type="host_has_session",
                        properties={
                            "user": user,
                            "terminal": sess.get("terminal", ""),
                            "login_time": sess.get("login_time", ""),
                            "from_host": sess.get("from_host", ""),
                            "timestamp_ms": envelope.timestamp_ms,
                        },
                    ))

        if category == "identity" and etype in {"risk_scored", "finding_created"}:
            # A risk scoring / finding about an identity: create identity_has_risk edge
            target_user = p.get("user", p.get("identity", ""))
            if target_user:
                identity_id = f"identity-{envelope.source.lower()}-{target_user.lower()}"
                edges.append(GraphRelationship(
                    source_id=asset_id,  # asset_id is the host/device
                    target_id=identity_id,
                    relationship_type="host_has_session",
                    properties={
                        "risk_score": p.get("risk_score", 0.0),
                        "severity": envelope.severity,
                        "title": envelope.description,
                        "timestamp_ms": envelope.timestamp_ms,
                    },
                ))

        elif category == "device" and etype in {"device_posture_observation"}:
            # Device posture: asset is the device, link to posture info
            pass  # The entity update above captures posture in properties

        return edges

    # -- diagnostics --

    def stats(self) -> dict[str, Any]:
        return {
            "entity_count": self._entity_count,
            "relationship_count": self._rel_count,
            "ingest_count": self._ingest_count,
            "entity_types": {},
            "relationship_types": {},
        }

    def summarize(self) -> str:
        """Human-readable summary of the graph contents."""
        ent_types: dict[str, int] = {}
        rel_types: dict[str, int] = {}
        for ent in self._entities.values():
            ent_types[ent.entity_type] = ent_types.get(ent.entity_type, 0) + 1
        for rel in self._relationships.values():
            rel_types[rel.relationship_type] = rel_types.get(rel.relationship_type, 0) + 1
        lines = [
            f"Security Graph: {self._entity_count} entities, {self._rel_count} relationships, {self._ingest_count} ingests",
            "Entities by type:",
        ]
        for t, c in sorted(ent_types.items()):
            lines.append(f"  {t}: {c}")
        lines.append("Relationships by type:")
        for t, c in sorted(rel_types.items()):
            lines.append(f"  {t}: {c}")
        return "\n".join(lines)


def clear_graph() -> None:
    """Reset the module-level singleton (for tests / demo)."""
    global _graph
    _graph = SecurityGraph()


def get_graph() -> SecurityGraph:
    """Return the module-level singleton (lazy-created)."""
    global _graph
    if _graph is None:
        _graph = SecurityGraph()
    return _graph


# Alias for backward compatibility with dashboard intake handler
get_security_graph = get_graph


# ---------------------------------------------------------------------------
# Module-level singleton (shared across the process)
# ---------------------------------------------------------------------------

_graph: SecurityGraph | None = None
