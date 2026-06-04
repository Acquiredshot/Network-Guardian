# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""Tests for per-device persistent baselines and lateral movement detection."""

from __future__ import annotations

import asyncio
import random
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from network_guardian.ai.anomaly import AnomalyScore
from network_guardian.ai.device_baseline import DeviceBaseline, DeviceBaselineManager
from network_guardian.ai.lateral_movement import LateralMovementAlert, LateralMovementDetector
from network_guardian.ai.nodes import DeviceBaselineNode, LateralMovementNode, NodeGraph
from network_guardian.core.events import Event, EventBus


# ===========================================================================
# DeviceBaseline (single device)
# ===========================================================================


class TestDeviceBaseline:
    """Unit tests for the single-device rolling baseline."""

    def _normal_features(self, n: int = 40, seed: int = 1) -> list[list[float]]:
        rng = random.Random(seed)
        # Simulate a device with stable metrics: [conn_rate≈5, cpu≈20, ports≈3]
        return [
            [5 + rng.gauss(0, 0.3), 20 + rng.gauss(0, 1.0), 3 + rng.gauss(0, 0.2)]
            for _ in range(n)
        ]

    def test_returns_none_during_warmup(self):
        bl = DeviceBaseline("10.0.0.1", min_samples=30)
        for feats in self._normal_features(29):
            result = bl.observe(feats)
        assert result is None
        assert not bl.is_fitted

    def test_fits_after_min_samples(self):
        bl = DeviceBaseline("10.0.0.1", min_samples=30)
        for feats in self._normal_features(30):
            bl.observe(feats)
        assert bl.is_fitted

    def test_normal_sample_scores_low(self):
        bl = DeviceBaseline("10.0.0.1", min_samples=30)
        data = self._normal_features(60)
        for feats in data:
            bl.observe(feats)
        result = bl.observe([5.0, 20.0, 3.0])
        assert result is not None
        assert result.score < 0.6  # well within normal baseline

    def test_anomalous_sample_scores_higher_than_normal(self):
        bl = DeviceBaseline("10.0.0.1", min_samples=30)
        data = self._normal_features(60)
        for feats in data:
            bl.observe(feats)
        normal_result = bl.observe([5.0, 20.0, 3.0])
        # Simulate ransomware: connection rate spikes 50x, CPU spikes
        anomaly_result = bl.observe([250.0, 95.0, 300.0])
        assert normal_result is not None
        assert anomaly_result is not None
        assert anomaly_result.score > normal_result.score

    def test_get_stats(self):
        bl = DeviceBaseline("10.0.0.1", min_samples=30)
        for feats in self._normal_features(35):
            bl.observe(feats)
        stats = bl.get_stats()
        assert stats["device_id"] == "10.0.0.1"
        assert stats["observations"] == 35
        assert stats["fitted"] is True

    def test_persistence_roundtrip(self):
        bl = DeviceBaseline("192.168.1.5", min_samples=30)
        data = self._normal_features(50)
        for feats in data:
            bl.observe(feats)
        d = bl.to_dict()
        restored = DeviceBaseline.from_dict(d)
        assert restored.device_id == "192.168.1.5"
        assert restored.is_fitted
        assert restored.observation_count == 50

    def test_observation_count_increments(self):
        bl = DeviceBaseline("10.0.0.1", min_samples=30)
        for i, feats in enumerate(self._normal_features(10), 1):
            bl.observe(feats)
            assert bl.observation_count == i


# ===========================================================================
# DeviceBaselineManager
# ===========================================================================


class TestDeviceBaselineManager:
    """Tests for the multi-device manager with persistence."""

    def _make_manager(self, tmp_path: Path) -> DeviceBaselineManager:
        return DeviceBaselineManager(data_dir=tmp_path, min_samples=20)

    def _normal_feats(self, n: int = 25) -> list[list[float]]:
        rng = random.Random(7)
        return [[rng.gauss(10, 1), rng.gauss(50, 2)] for _ in range(n)]

    def test_creates_baseline_on_first_observe(self, tmp_path):
        mgr = self._make_manager(tmp_path)
        mgr.observe("10.0.0.1", [1.0, 2.0])
        assert mgr.get_baseline("10.0.0.1") is not None

    def test_returns_none_during_warmup(self, tmp_path):
        mgr = self._make_manager(tmp_path)
        for feats in self._normal_feats(19):
            result = mgr.observe("10.0.0.1", feats)
        assert result is None

    def test_returns_score_after_warmup(self, tmp_path):
        mgr = self._make_manager(tmp_path)
        for feats in self._normal_feats(25):
            result = mgr.observe("10.0.0.1", feats)
        assert result is not None
        assert isinstance(result, AnomalyScore)

    def test_multiple_devices_independent(self, tmp_path):
        mgr = self._make_manager(tmp_path)
        rng = random.Random(42)
        # Device A: stable at ~10
        for _ in range(25):
            mgr.observe("10.0.0.1", [rng.gauss(10, 0.5)])
        # Device B: stable at ~100
        for _ in range(25):
            mgr.observe("10.0.0.2", [rng.gauss(100, 0.5)])
        # Both should be fitted and independent
        assert mgr.get_baseline("10.0.0.1").is_fitted
        assert mgr.get_baseline("10.0.0.2").is_fitted

    def test_get_stats(self, tmp_path):
        mgr = self._make_manager(tmp_path)
        for feats in self._normal_feats(25):
            mgr.observe("10.0.0.1", feats)
        stats = mgr.get_stats()
        assert stats["total_devices"] == 1
        assert stats["fitted_devices"] == 1
        assert stats["total_observations"] == 25

    def test_save_and_reload(self, tmp_path):
        mgr = self._make_manager(tmp_path)
        for feats in self._normal_feats(25):
            mgr.observe("10.0.0.5", feats)
        mgr.save()
        # New manager loads from disk
        mgr2 = self._make_manager(tmp_path)
        baseline = mgr2.get_baseline("10.0.0.5")
        assert baseline is not None
        assert baseline.is_fitted

    def test_save_graceful_on_bad_dir(self, tmp_path):
        """save() should not raise even on a weird path."""
        mgr = DeviceBaselineManager(data_dir=tmp_path / "baselines", min_samples=5)
        mgr.observe("1.2.3.4", [1.0])
        mgr.save()  # should not raise


# ===========================================================================
# LateralMovementDetector
# ===========================================================================


class TestLateralMovementDetector:
    """Tests for the fan-out spike detector."""

    def _make_detector(self, tmp_path: Path, **kwargs) -> LateralMovementDetector:
        return LateralMovementDetector(data_dir=tmp_path, **kwargs)

    def _build_history(
        self, detector: LateralMovementDetector, src: str, n_windows: int, fan_out: int
    ) -> None:
        """Manually inject historical fan-out counts for *src*."""
        from collections import deque
        dq = detector._history[src]
        for _ in range(n_windows):
            dq.append(fan_out)

    def test_no_alert_without_baseline(self, tmp_path):
        det = self._make_detector(tmp_path, min_baseline_periods=5, spike_absolute_threshold=999)
        result = det.observe_connection("10.0.0.1", "10.0.0.2")
        assert result is None

    def test_absolute_alert_without_baseline(self, tmp_path):
        det = self._make_detector(tmp_path, min_baseline_periods=5, spike_absolute_threshold=5)
        # Immediately drive fanout to 6 unique destinations
        for i in range(6):
            det.observe_connection("10.0.0.1", f"10.0.0.{100 + i}")
        # The 6th observation should trigger the absolute threshold
        result = det.observe_connection("10.0.0.1", "10.0.0.199")
        assert result is not None
        assert result.is_alert is True

    def test_no_alert_for_normal_fanout(self, tmp_path):
        det = self._make_detector(
            tmp_path,
            min_baseline_periods=5,
            spike_z_threshold=3.0,
            spike_absolute_threshold=50,
        )
        # Build baseline: src talks to 3 destinations per window
        self._build_history(det, "192.168.1.10", n_windows=10, fan_out=3)
        # Normal: 3 connections this window
        for i in range(3):
            det.observe_connection("192.168.1.10", f"192.168.1.{200 + i}")
        result = det.observe_connection("192.168.1.10", "192.168.1.203")
        # fan_out is 4, baseline mean=3, std≈0 → use ratio; z=(4/3)-1=0.33 < 3.0
        assert result is None or result.is_alert is False

    def test_alert_on_spike(self, tmp_path):
        det = self._make_detector(
            tmp_path,
            min_baseline_periods=5,
            spike_z_threshold=3.0,
            spike_absolute_threshold=999,
        )
        # Baseline: src contacts exactly 3 unique IPs per window (std≈0)
        self._build_history(det, "192.168.1.10", n_windows=10, fan_out=3)
        # Simulate ransomware: contact 50 unique destinations
        for i in range(50):
            det.observe_connection("192.168.1.10", f"10.0.{i // 256}.{i % 256}")
        result = det.observe_connection("192.168.1.10", "10.0.1.255")
        assert result is not None
        assert result.is_alert is True
        assert result.src_ip == "192.168.1.10"

    def test_z_score_meaningful(self, tmp_path):
        rng = random.Random(42)
        det = self._make_detector(tmp_path, min_baseline_periods=5, spike_absolute_threshold=999)
        # Build varied history (mean≈10, std≈2)
        for _ in range(10):
            det._history["10.0.0.1"].append(int(rng.gauss(10, 2)))
        # Normal observation: 10 connections
        for i in range(10):
            det.observe_connection("10.0.0.1", f"10.0.1.{i}")
        result = det._score("10.0.0.1", __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
        assert result is not None
        assert abs(result.z_score) < 3.0  # within baseline

    def test_alert_dataclass_fields(self, tmp_path):
        det = self._make_detector(tmp_path, min_baseline_periods=2, spike_absolute_threshold=3)
        self._build_history(det, "10.1.1.1", n_windows=3, fan_out=1)
        for i in range(10):
            det.observe_connection("10.1.1.1", f"172.16.0.{i}")
        result = det.observe_connection("10.1.1.1", "172.16.0.100")
        assert result is not None
        assert result.is_alert is True
        d = result.as_dict()
        assert "src_ip" in d
        assert "current_fanout" in d
        assert "z_score" in d
        assert "dst_ips" in d

    def test_stats(self, tmp_path):
        det = self._make_detector(tmp_path)
        det.observe_connection("1.2.3.4", "5.6.7.8")
        stats = det.get_stats()
        assert stats["total_connections_observed"] == 1
        assert "tracked_sources" in stats

    def test_save_and_reload(self, tmp_path):
        det = self._make_detector(tmp_path, min_baseline_periods=3)
        self._build_history(det, "10.0.0.1", n_windows=5, fan_out=4)
        det.save()
        det2 = self._make_detector(tmp_path)
        assert len(det2._history["10.0.0.1"]) == 5

    def test_window_roll(self, tmp_path):
        """_roll_window archives current window into history."""
        det = self._make_detector(tmp_path, window_seconds=300)
        for i in range(5):
            det.observe_connection("10.0.0.1", f"10.0.0.{100 + i}")
        before = len(det._history["10.0.0.1"])
        det._roll_window(__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
        after = len(det._history["10.0.0.1"])
        assert after == before + 1


# ===========================================================================
# DeviceBaselineNode (async node integration)
# ===========================================================================


class TestDeviceBaselineNode:
    """Tests for the AINode that wraps DeviceBaselineManager."""

    @pytest.mark.asyncio
    async def test_node_starts_and_creates_manager(self, tmp_path):
        bus = EventBus()
        node = DeviceBaselineNode(bus)
        await node.start()
        assert node._manager is not None
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_ignores_missing_features(self, tmp_path):
        bus = EventBus()
        node = DeviceBaselineNode(bus)
        await node.start()
        # Event with no useful fields — should not crash
        evt = Event(topic="sensor.metrics", data={"nothing": "here"})
        await node.process(evt)
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_processes_metric_event(self):
        bus = EventBus()
        node = DeviceBaselineNode(bus)
        await node.start()
        for i in range(35):
            evt = Event(
                topic="monitor.metric_recorded",
                data={
                    "host": "192.168.0.5",
                    "features": [float(i % 10), float(i % 5), float(i % 3)],
                },
            )
            await node.process(evt)
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_processes_ids_alert(self):
        bus = EventBus()
        node = DeviceBaselineNode(bus)
        await node.start()
        for _ in range(35):
            evt = Event(
                topic="ids.alert",
                data={
                    "alert": {
                        "source_ip": "10.10.0.1",
                        "destination_ip": "10.10.0.2",
                        "severity": "high",
                        "source_port": 12345,
                        "destination_port": 443,
                    }
                },
            )
            await node.process(evt)
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_publishes_alert_on_anomaly(self):
        """After enough normal observations, a wildly anomalous one triggers a publish."""
        bus = EventBus()
        node = DeviceBaselineNode(bus)
        await node.start()

        published = []

        async def capture(event: Event) -> None:
            published.append(event)

        bus.subscribe("ai.device_baseline_alert", capture)

        rng = random.Random(42)
        # Feed 40 stable observations
        for _ in range(40):
            evt = Event(
                topic="monitor.metric_recorded",
                data={
                    "host": "192.168.1.99",
                    "features": [
                        rng.gauss(5, 0.1),
                        rng.gauss(10, 0.1),
                        rng.gauss(2, 0.1),
                    ],
                },
            )
            await node.process(evt)

        # Feed one extreme outlier — 50× the normal values
        outlier = Event(
            topic="monitor.metric_recorded",
            data={
                "host": "192.168.1.99",
                "features": [500.0, 1000.0, 200.0],
            },
        )
        await node.process(outlier)
        await node.stop()

        assert len(published) >= 1
        assert published[0].data["message"].payload["device_id"] == "192.168.1.99"

    @pytest.mark.asyncio
    async def test_node_skips_ids_alert_with_unknown_src(self):
        bus = EventBus()
        node = DeviceBaselineNode(bus)
        await node.start()
        evt = Event(
            topic="ids.alert",
            data={"alert": {"source_ip": "unknown", "severity": "low"}},
        )
        await node.process(evt)  # must not crash
        await node.stop()


# ===========================================================================
# LateralMovementNode (async node integration)
# ===========================================================================


class TestLateralMovementNode:
    """Tests for the AINode that wraps LateralMovementDetector."""

    @pytest.mark.asyncio
    async def test_node_starts_and_creates_detector(self):
        bus = EventBus()
        node = LateralMovementNode(bus)
        await node.start()
        assert node._detector is not None
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_ignores_events_without_dst(self):
        bus = EventBus()
        node = LateralMovementNode(bus)
        await node.start()
        evt = Event(
            topic="ids.alert",
            data={"alert": {"source_ip": "10.0.0.1", "destination_ip": ""}},
        )
        await node.process(evt)  # must not crash
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_publishes_on_spike(self):
        bus = EventBus()
        node = LateralMovementNode(bus)
        await node.start()

        published = []

        async def capture(event: Event) -> None:
            published.append(event)

        bus.subscribe("ai.lateral_movement_alert", capture)

        # Set up baseline: 2 unique dests per window
        node._detector._history["10.0.0.1"].extend([2] * 6)

        # Now spam 30 unique destinations → spike
        for i in range(30):
            evt = Event(
                topic="ids.alert",
                data={
                    "alert": {
                        "source_ip": "10.0.0.1",
                        "destination_ip": f"172.16.{i // 256}.{i % 256}",
                        "severity": "medium",
                    }
                },
            )
            await node.process(evt)

        await node.stop()
        assert len(published) >= 1
        payload = published[0].data["message"].payload
        assert payload["src_ip"] == "10.0.0.1"
        assert payload["is_alert"] is True

    @pytest.mark.asyncio
    async def test_node_no_alert_for_normal_traffic(self):
        bus = EventBus()
        node = LateralMovementNode(bus)
        await node.start()

        published = []

        async def capture(event: Event) -> None:
            published.append(event)

        bus.subscribe("ai.lateral_movement_alert", capture)

        # Baseline: 5 unique dests per window
        node._detector._history["10.0.0.2"].extend([5] * 8)

        # Normal: contact 4 unique destinations (well within baseline)
        for i in range(4):
            evt = Event(
                topic="ids.alert",
                data={
                    "alert": {
                        "source_ip": "10.0.0.2",
                        "destination_ip": f"10.0.1.{i}",
                        "severity": "low",
                    }
                },
            )
            await node.process(evt)

        await node.stop()
        assert len(published) == 0


# ===========================================================================
# NodeGraph integration
# ===========================================================================


class TestNodeGraphIntegration:
    """Verify the two new nodes register cleanly in the default graph."""

    @pytest.mark.asyncio
    async def test_default_graph_contains_new_nodes(self):
        bus = EventBus()
        graph = NodeGraph.create_default(bus)
        assert "device_baseline_node" in graph.node_names
        assert "lateral_movement_node" in graph.node_names

    @pytest.mark.asyncio
    async def test_default_graph_starts_and_stops(self):
        bus = EventBus()
        graph = NodeGraph.create_default(bus)
        await graph.start_all()
        health = graph.health_all()
        names = [h["node"] for h in health]
        assert "device_baseline_node" in names
        assert "lateral_movement_node" in names
        await graph.stop_all()

    @pytest.mark.asyncio
    async def test_engine_exposes_lazy_properties(self):
        from network_guardian.core.engine import Engine
        engine = Engine()
        assert engine.device_baseline_manager is not None
        assert engine.lateral_movement_detector is not None
        # Same instance on repeated access
        assert engine.device_baseline_manager is engine.device_baseline_manager
        assert engine.lateral_movement_detector is engine.lateral_movement_detector
