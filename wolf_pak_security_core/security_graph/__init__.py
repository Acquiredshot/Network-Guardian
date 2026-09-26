# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Wolf-Pak Security Core — Security Graph.

Entity-relationship graph that binds together assets, identities, threats,
vulnerabilities, and security events into a unified context model.

Node types:
    - Asset (from Mask Network discovery)
    - Identity (from Pakshield identity risk)
    - Threat (IOC/threat-feed correlation)
    - Vulnerability (exposure/CVE assessment)
    - Event (SecurityEvent from the Event Fabric)

Relationship edges connect nodes to support:
    - "accessed_from" (identity → asset)
    - "resides_on" (identity → asset)
    - "exploits" (threat → vulnerability)
    - "affects" (vulnerability → asset)
    - "observed_in" (event → asset/identity/threat)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(Enum):
    ASSET = "asset"
    IDENTITY = "identity"
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    EVENT = "event"


@dataclass
class GraphNode:
    """A single node in the security graph."""

    id: str
    type: NodeType
    labels: set[str] = field(default_factory=set)
    properties: dict[str, Any] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "labels": sorted(self.labels),
            "property_keys": sorted(self.properties.keys()),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class GraphEdge:
    """A directed relationship between two graph nodes."""

    source: str
    target: str
    relation: str
    properties: dict[str, Any] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0


class SecurityGraph:
    """Phase 1 security graph — in-memory entity-relationship store."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    def upsert_node(self, node: GraphNode) -> GraphNode:
        """Insert or update a node in the graph."""
        now = node.first_seen or 0.0
        if node.id in self._nodes:
            existing = self._nodes[node.id]
            existing.labels |= node.labels
            existing.properties.update(node.properties)
            if node.last_seen:
                existing.last_seen = node.last_seen
        else:
            node.first_seen = now or 0.0
            self._nodes[node.id] = node
        return self._nodes[node.id]

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def find_nodes(self, type: NodeType | None = None, label: str | None = None) -> list[GraphNode]:
        """Find nodes by type and/or label."""
        results: list[GraphNode] = []
        for node in self._nodes.values():
            if type is not None and node.type != type:
                continue
            if label is not None and label not in node.labels:
                continue
            results.append(node)
        return results

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------

    def add_edge(self, source: str, target: str, relation: str, **properties: Any) -> GraphEdge:
        """Add a directed edge between two existing nodes."""
        edge = GraphEdge(
            source=source,
            target=target,
            relation=relation,
            properties=properties,
            first_seen=0.0,
            last_seen=0.0,
        )
        self._edges.append(edge)
        return edge

    def get_edges_for_node(self, node_id: str) -> list[GraphEdge]:
        """Return all edges touching a node (in or out)."""
        return [e for e in self._edges if e.source == node_id or e.target == node_id]

    def get_neighbors(self, node_id: str, relation: str | None = None) -> list[tuple[str, str]]:
        """Return (neighbor_id, relation) pairs for a node."""
        results: list[tuple[str, str]] = []
        for edge in self._edges:
            if edge.source == node_id:
                if relation is None or edge.relation == relation:
                    results.append((edge.target, edge.relation))
            elif edge.target == node_id:
                if relation is None or edge.relation == relation:
                    results.append((edge.source, f"{edge.relation}_inverted"))
        return results

    # ------------------------------------------------------------------
    # Bulk ingestion helpers
    # ------------------------------------------------------------------

    def ingest_asset(self, asset: dict[str, Any]) -> GraphNode:
        """Ingest a Mask Network asset as a graph node."""
        node_id = asset.get("id", f"asset-{asset.get('address', 'unknown')}")
        node = GraphNode(
            id=node_id,
            type=NodeType.ASSET,
            labels={"asset", "discovered"},
            properties={
                "address": asset.get("address", ""),
                "name": asset.get("name", ""),
                "open_ports": asset.get("open_ports", []),
                "services": asset.get("services", []),
                "confidence": asset.get("confidence", 0.0),
            },
            first_seen=asset.get("first_seen", 0.0),
            last_seen=asset.get("last_seen", 0.0),
        )
        return self.upsert_node(node)

    def ingest_identity_risk(self, identity_id: str, score: dict[str, Any]) -> GraphNode:
        """Ingest a Pakshield identity risk score as a graph node."""
        node = GraphNode(
            id=f"identity-{identity_id}",
            type=NodeType.IDENTITY,
            labels={"identity", "risk-scored"},
            properties={
                "score": score.get("score", 0),
                "level": score.get("level", "low"),
                "factors": score.get("factors", {}),
                "reason": score.get("reason", ""),
            },
            first_seen=score.get("timestamp", 0.0),
        )
        return self.upsert_node(node)

    def ingest_threat_mapping(self, mapping: dict[str, Any]) -> GraphNode:
        """Ingest a Mask Network threat mapping as a graph node."""
        node_id = f"threat-{mapping.get('asset_id', '')}-{mapping.get('source', '')}"
        node = GraphNode(
            id=node_id,
            type=NodeType.THREAT,
            labels={"threat", "ioc"},
            properties={
                "asset_id": mapping.get("asset_id", ""),
                "threat_type": mapping.get("threat_type", ""),
                "severity": mapping.get("severity", "low"),
                "source": mapping.get("source", ""),
                "detail": mapping.get("detail", ""),
            },
            first_seen=mapping.get("timestamp", 0.0),
        )
        return self.upsert_node(node)

    def ingest_vulnerability(self, vuln: dict[str, Any]) -> GraphNode:
        """Ingest a Mask Network vulnerability as a graph node."""
        node_id = vuln.get("vuln_id", f"vuln-{vuln.get('asset_id', '')}")
        node = GraphNode(
            id=node_id,
            type=NodeType.VULNERABILITY,
            labels={"vulnerability", "exposure"},
            properties={
                "asset_id": vuln.get("asset_id", ""),
                "title": vuln.get("title", ""),
                "severity": vuln.get("severity", "low"),
                "cvss": vuln.get("cvss", 0.0),
                "description": vuln.get("description", ""),
            },
            first_seen=vuln.get("timestamp", 0.0),
        )
        return self.upsert_node(node)
