# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
ROS-Inspired Node Framework — reactive compute graph for AI components.

Adapts the Robot Operating System (ROS) publish-subscribe node architecture
to network security.  Each **AINode** is an independent processing unit
that subscribes to topics on the shared :class:`EventBus`, processes
incoming data through its ``process`` callback, and publishes results to
downstream topics.

Key concepts:
- **AINode**: a named, lifecycle-managed processing unit with typed I/O.
- **NodeGraph**: a registry that wires nodes together, starts / stops them
  as a group, and exposes health telemetry.
- **Messages**: thin wrappers carried inside :class:`Event.data` dicts.

The graph is deliberately framework-agnostic — it uses the same
``EventBus`` that the rest of Network Guardian already relies on.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.ai.nodes")


# ---------------------------------------------------------------------------
# Node lifecycle
# ---------------------------------------------------------------------------


class NodeState(Enum):
    """Lifecycle states for an AINode."""

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


@dataclass
class NodeMessage:
    """Typed message passed between nodes via the EventBus."""

    source_node: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Base AINode
# ---------------------------------------------------------------------------


class AINode(ABC):
    """An independent AI processing unit (inspired by ROS nodes).

    Subclasses implement :meth:`process` which receives an ``Event`` and
    may publish zero or more result events to ``output_topics``.
    """

    name: str = "base_node"

    def __init__(
        self,
        event_bus: EventBus,
        *,
        input_topics: list[str] | None = None,
        output_topics: list[str] | None = None,
        rate_limit_hz: float = 0.0,
    ) -> None:
        self.event_bus = event_bus
        self.input_topics: list[str] = input_topics or []
        self.output_topics: list[str] = output_topics or []
        self._rate_limit_hz = rate_limit_hz
        self._state = NodeState.CREATED
        self._messages_in = 0
        self._messages_out = 0
        self._errors = 0
        self._last_process_time: float = 0.0
        self._started_at: datetime | None = None

    # -- Lifecycle -------------------------------------------------------

    async def start(self) -> None:
        """Subscribe to input topics and mark the node as running."""
        self._state = NodeState.STARTING
        for topic in self.input_topics:
            self.event_bus.subscribe(topic, self._on_event)
        self._state = NodeState.RUNNING
        self._started_at = datetime.now(timezone.utc)
        await asyncio.sleep(0)
        logger.info("Node started: %s (inputs=%s, outputs=%s)",
                     self.name, self.input_topics, self.output_topics)

    async def stop(self) -> None:
        """Unsubscribe from all topics and mark as stopped."""
        self._state = NodeState.STOPPING
        for topic in self.input_topics:
            self.event_bus.unsubscribe(topic, self._on_event)
        self._state = NodeState.STOPPED
        await asyncio.sleep(0)
        logger.info("Node stopped: %s (processed=%d, errors=%d)",
                     self.name, self._messages_in, self._errors)

    @property
    def state(self) -> NodeState:
        return self._state

    # -- Processing loop -------------------------------------------------

    async def _on_event(self, event: Event) -> None:
        """Internal handler wired to the EventBus."""
        # Rate limiting
        if self._rate_limit_hz > 0:
            min_interval = 1.0 / self._rate_limit_hz
            elapsed = time.monotonic() - self._last_process_time
            if elapsed < min_interval:
                return

        self._messages_in += 1
        self._last_process_time = time.monotonic()
        try:
            await self.process(event)
        except Exception:
            self._errors += 1
            self._state = NodeState.ERROR
            logger.exception("Node %s error processing event %s", self.name, event.topic)

    @abstractmethod
    async def process(self, event: Event) -> None:
        """Handle an incoming event.  Override in subclasses."""

    # -- Publishing helpers ----------------------------------------------

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        """Publish a message to *topic* (must be in ``output_topics``)."""
        msg = NodeMessage(source_node=self.name, payload=payload)
        await self.event_bus.publish(Event(topic=topic, data={"message": msg}))
        self._messages_out += 1

    # -- Telemetry -------------------------------------------------------

    def health(self) -> dict[str, Any]:
        return {
            "node": self.name,
            "state": self._state.value,
            "messages_in": self._messages_in,
            "messages_out": self._messages_out,
            "errors": self._errors,
            "started_at": self._started_at.isoformat() if self._started_at else None,
        }


# ---------------------------------------------------------------------------
# Concrete AI Nodes
# ---------------------------------------------------------------------------


class AnomalyDetectionNode(AINode):
    """Subscribes to metric events, scores them with the ensemble detector."""

    name = "anomaly_detection_node"

    def __init__(self, event_bus: EventBus, **kwargs: Any) -> None:
        super().__init__(
            event_bus,
            input_topics=["sensor.metrics", "monitor.metric_recorded"],
            output_topics=["ai.anomaly_scored"],
            **kwargs,
        )
        self._detector = None

    async def start(self) -> None:
        from network_guardian.ai.anomaly import EnsembleDetector, IsolationForest, OneClassSVM
        self._detector = EnsembleDetector()
        self._detector.add_detector(IsolationForest(n_trees=50, max_samples=128, seed=42))
        self._detector.add_detector(OneClassSVM(nu=0.1, seed=42))
        await super().start()

    async def process(self, event: Event) -> None:
        features = event.data.get("features") or event.data.get("values")
        if features is None:
            return
        if not isinstance(features, list):
            features = [float(features)]
        result = self._detector.score(features)
        await self.publish("ai.anomaly_scored", {
            "score": result.score,
            "is_anomaly": result.is_anomaly,
            "method": result.method,
            "source_topic": event.topic,
        })


class ForecastNode(AINode):
    """Receives time-series data and publishes forecasts."""

    name = "forecast_node"

    def __init__(self, event_bus: EventBus, **kwargs: Any) -> None:
        super().__init__(
            event_bus,
            input_topics=["sensor.timeseries", "training.series_ready"],
            output_topics=["ai.forecast_ready"],
            **kwargs,
        )
        self._forecaster = None

    async def start(self) -> None:
        from network_guardian.ai.forecasting import ARIMAForecaster
        self._forecaster = ARIMAForecaster(p=3, d=1, q=1)
        await super().start()

    async def process(self, event: Event) -> None:
        series = event.data.get("series")
        steps = event.data.get("steps", 10)
        if not series or len(series) < 10:
            return
        diag = self._forecaster.fit(series)
        if "error" in diag:
            return
        result = self._forecaster.predict(steps)
        await self.publish("ai.forecast_ready", {
            "method": result.method,
            "points": [{"step": p.step, "value": p.value,
                         "lower": p.lower, "upper": p.upper}
                        for p in result.points],
            "metrics": result.metrics,
        })


_TOPIC_AUDIT_FINDINGS = "ai.audit_findings"


class AuditAnalysisNode(AINode):
    """Receives host lists and publishes risk profiles."""

    name = "audit_analysis_node"

    def __init__(self, event_bus: EventBus, **kwargs: Any) -> None:
        super().__init__(
            event_bus,
            input_topics=["scanner.hosts_discovered", "auditor.scan_complete"],
            output_topics=["ai.risk_profiles", _TOPIC_AUDIT_FINDINGS],
            **kwargs,
        )
        self._analyzer = None

    async def start(self) -> None:
        from network_guardian.ai.audit_analyzer import NetworkAuditAnalyzer
        self._analyzer = NetworkAuditAnalyzer()
        await super().start()

    async def process(self, event: Event) -> None:
        hosts = event.data.get("hosts", [])
        if not hosts:
            return
        profiles = self._analyzer.analyse(hosts)
        await self.publish("ai.risk_profiles", {
            "profiles": [
                {"host_ip": p.host_ip, "risk_score": p.risk_score,
                 "open_ports": p.open_port_count,
                 "high_risk_services": p.high_risk_services,
                 "anomaly_score": p.anomaly_score}
                for p in profiles
            ],
        })
        all_findings = []
        for p in profiles:
            all_findings.extend(p.findings)
        if all_findings:
            await self.publish(_TOPIC_AUDIT_FINDINGS, {
                "finding_count": len(all_findings),
                "critical": sum(1 for f in all_findings
                                if f.severity.value in ("high", "critical")),
            })


class TaskRecommendationNode(AINode):
    """Receives findings and recommends automated tasks."""

    name = "task_recommendation_node"

    def __init__(self, event_bus: EventBus, **kwargs: Any) -> None:
        super().__init__(
            event_bus,
            input_topics=[_TOPIC_AUDIT_FINDINGS, "auditor.findings_ready"],
            output_topics=["ai.task_recommendations"],
            **kwargs,
        )
        self._automation = None

    async def start(self) -> None:
        from network_guardian.ai.smart_automation import SmartAutomation
        self._automation = SmartAutomation()
        await super().start()

    async def process(self, event: Event) -> None:
        findings = event.data.get("findings", [])
        available = event.data.get("available_tasks", [])
        if not findings:
            return
        recs = self._automation.recommend_tasks(findings, available)
        await self.publish("ai.task_recommendations", {
            "recommendations": [
                {"task": r.task_name, "priority": r.priority,
                 "success_prob": r.estimated_success, "reason": r.reason}
                for r in recs
            ],
        })


# ---------------------------------------------------------------------------
# DeviceBaselineNode — per-device persistent behavioral baselines
# ---------------------------------------------------------------------------


class DeviceBaselineNode(AINode):
    """Scores each device's current metrics against its own rolling baseline.

    Subscribes to metric and IDS events.  Publishes to
    ``ai.device_baseline_alert`` whenever a device deviates from its
    personal baseline (not the fleet average).
    """

    name = "device_baseline_node"

    def __init__(self, event_bus: EventBus, **kwargs: Any) -> None:
        super().__init__(
            event_bus,
            input_topics=[
                "sensor.metrics",
                "monitor.metric_recorded",
                "ids.alert",
            ],
            output_topics=["ai.device_baseline_alert"],
            **kwargs,
        )
        self._manager = None

    async def start(self) -> None:
        from network_guardian.ai.device_baseline import DeviceBaselineManager
        self._manager = DeviceBaselineManager()
        await super().start()

    async def process(self, event: Event) -> None:
        device_id, features = self._extract(event)
        if not device_id or not features:
            return

        result = self._manager.observe(device_id, features)
        if result is None:
            return  # still warming up

        if result.is_anomaly:
            await self.publish("ai.device_baseline_alert", {
                "device_id": device_id,
                "anomaly_score": result.score,
                "method": result.method,
                "source_topic": event.topic,
                "details": result.details,
            })

    @staticmethod
    def _extract(event: Event) -> tuple[str, list[float]]:
        """Pull (device_id, feature_vector) out of the event payload."""
        data = event.data

        # IDS alert: use source_ip as device_id, connection/port features
        if event.topic == "ids.alert":
            alert = data.get("alert", {})
            src = alert.get("source_ip", "")
            if not src or src == "unknown":
                return "", []
            # Feature: [severity_num, has_dst_ip, src_port, dst_port]
            sev_map = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
            sev = sev_map.get(alert.get("severity", ""), 1.0)
            has_dst = 1.0 if alert.get("destination_ip") else 0.0
            src_port = float(alert.get("source_port", 0))
            dst_port = float(alert.get("destination_port", 0))
            return src, [sev, has_dst, src_port, dst_port]

        # Metric event: use host/device field + numeric values
        host = (
            data.get("host")
            or data.get("device_id")
            or data.get("source_ip")
            or ""
        )
        if not host:
            return "", []

        raw_features = data.get("features") or data.get("values")
        if raw_features is None:
            # Try to pull named numeric fields
            raw_features = [
                v for v in data.values()
                if isinstance(v, (int, float)) and not isinstance(v, bool)
            ]
        if not raw_features:
            return "", []

        try:
            features = [float(x) for x in raw_features]
        except (TypeError, ValueError):
            return "", []

        return host, features


# ---------------------------------------------------------------------------
# LateralMovementNode — connection fan-out spike detection
# ---------------------------------------------------------------------------


class LateralMovementNode(AINode):
    """Detects lateral movement (ransomware, worms, recon) via fan-out spikes.

    Observes every ``ids.alert`` event's ``source_ip → destination_ip`` pair.
    When a source IP's unique destination count spikes above its baseline,
    publishes a ``ai.lateral_movement_alert``.
    """

    name = "lateral_movement_node"

    def __init__(self, event_bus: EventBus, **kwargs: Any) -> None:
        super().__init__(
            event_bus,
            input_topics=["ids.alert"],
            output_topics=["ai.lateral_movement_alert"],
            **kwargs,
        )
        self._detector = None

    async def start(self) -> None:
        from network_guardian.ai.lateral_movement import LateralMovementDetector
        self._detector = LateralMovementDetector()
        await super().start()

    async def process(self, event: Event) -> None:
        alert = event.data.get("alert", {})
        src_ip = alert.get("source_ip", "")
        dst_ip = alert.get("destination_ip", "")

        if not src_ip or src_ip == "unknown" or not dst_ip:
            return

        result = self._detector.observe_connection(src_ip, dst_ip)
        if result is None or not result.is_alert:
            return

        await self.publish("ai.lateral_movement_alert", result.as_dict())
        logger.warning(
            "LateralMovementNode: ALERT src=%s fanout=%d z=%.1f",
            src_ip, result.current_fanout, result.z_score,
        )


# ---------------------------------------------------------------------------
# Node Graph — manages a full compute-graph lifecycle
# ---------------------------------------------------------------------------


class NodeGraph:
    """Registry and lifecycle manager for a set of AINodes.

    Similar to a ROS launch file — declares which nodes participate,
    wires them to a shared ``EventBus``, and manages start/stop ordering.
    """

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._nodes: dict[str, AINode] = {}

    def add_node(self, node: AINode) -> None:
        if node.name in self._nodes:
            raise ValueError(f"Node already registered: {node.name}")
        self._nodes[node.name] = node
        logger.info("NodeGraph: registered %s", node.name)

    def get_node(self, name: str) -> AINode:
        return self._nodes[name]

    async def start_all(self) -> None:
        """Start every registered node."""
        for node in self._nodes.values():
            await node.start()
        logger.info("NodeGraph: all %d nodes started", len(self._nodes))

    async def stop_all(self) -> None:
        """Stop every registered node (reverse order)."""
        for node in reversed(list(self._nodes.values())):
            await node.stop()
        logger.info("NodeGraph: all nodes stopped")

    def health_all(self) -> list[dict[str, Any]]:
        return [node.health() for node in self._nodes.values()]

    @property
    def node_names(self) -> list[str]:
        return list(self._nodes.keys())

    def topology(self) -> dict[str, dict[str, list[str]]]:
        """Return the wiring topology of the graph.

        Returns a dict mapping node name → {"inputs": [...], "outputs": [...]}
        """
        return {
            name: {"inputs": node.input_topics, "outputs": node.output_topics}
            for name, node in self._nodes.items()
        }

    @classmethod
    def create_default(cls, event_bus: EventBus) -> NodeGraph:
        """Build the standard Network Guardian AI node graph."""
        graph = cls(event_bus)
        graph.add_node(AnomalyDetectionNode(event_bus))
        graph.add_node(ForecastNode(event_bus))
        graph.add_node(AuditAnalysisNode(event_bus))
        graph.add_node(TaskRecommendationNode(event_bus))
        graph.add_node(DeviceBaselineNode(event_bus))
        graph.add_node(LateralMovementNode(event_bus))
        return graph
