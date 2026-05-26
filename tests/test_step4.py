# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""Comprehensive tests for Step 4 — ROS-inspired node framework,
training pipeline, dataset generators, and engine integration."""

from __future__ import annotations

import math
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone

from network_guardian.ai.datasets import (
    CSVDatasetLoader,
    DataLabel,
    DataPoint,
    Dataset,
    MetricTimeSeriesGenerator,
    NetworkTrafficGenerator,
    compute_statistics,
    normalise_features,
)
from network_guardian.ai.nodes import (
    AINode,
    AnomalyDetectionNode,
    AuditAnalysisNode,
    ForecastNode,
    NodeGraph,
    NodeMessage,
    NodeState,
    TaskRecommendationNode,
)
from network_guardian.ai.training import (
    ModelRegistry,
    ModelSnapshot,
    TrainingPipeline,
    TrainingReport,
)
from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.core.events import Event, EventBus
from network_guardian.models.network import Finding, Host, HostStatus, Severity


# ===================================================================
# Datasets — synthetic generators
# ===================================================================


class TestNetworkTrafficGenerator:
    def test_generate_default(self):
        gen = NetworkTrafficGenerator(seed=42)
        ds = gen.generate()
        assert len(ds) == 950  # 800 + 50 + 50 + 50
        assert ds.feature_names == NetworkTrafficGenerator.FEATURE_NAMES
        assert len(ds.feature_names) == 8

    def test_custom_sizes(self):
        gen = NetworkTrafficGenerator(seed=1)
        ds = gen.generate(n_normal=100, n_anomaly=10, n_attack=5, n_scan=5)
        assert len(ds) == 120

    def test_label_distribution(self):
        gen = NetworkTrafficGenerator(seed=10)
        ds = gen.generate(n_normal=80, n_anomaly=10, n_attack=5, n_scan=5)
        labels = ds.labels()
        assert labels.count("normal") == 80
        assert labels.count("anomaly") == 10
        assert labels.count("attack") == 5
        assert labels.count("scan") == 5

    def test_feature_matrix_shape(self):
        gen = NetworkTrafficGenerator(seed=0)
        ds = gen.generate(n_normal=50, n_anomaly=5, n_attack=5, n_scan=5)
        matrix = ds.feature_matrix()
        assert len(matrix) == 65
        assert all(len(row) == 8 for row in matrix)


class TestMetricTimeSeriesGenerator:
    def test_generate_length(self):
        gen = MetricTimeSeriesGenerator(seed=42)
        ds, series = gen.generate(length=100, period=24)
        assert len(ds) == 100
        assert len(series) == 100

    def test_anomaly_injection(self):
        gen = MetricTimeSeriesGenerator(seed=42)
        ds, _ = gen.generate(length=200, anomaly_fraction=0.1)
        anomaly_count = sum(1 for dp in ds.points if dp.label == DataLabel.ANOMALY)
        assert anomaly_count == 20  # 10% of 200


# ===================================================================
# Datasets — CSV loader
# ===================================================================


class TestCSVDatasetLoader:
    def test_load_basic_csv(self):
        csv_text = "a,b,c\n1.0,2.0,3.0\n4.0,5.0,6.0\n7.0,8.0,9.0\n"
        loader = CSVDatasetLoader()
        ds = loader.load_string(csv_text, name="test_csv")
        assert len(ds) == 3
        assert ds.feature_names == ["a", "b", "c"]
        assert ds.points[0].features == [1.0, 2.0, 3.0]

    def test_load_with_label_column(self):
        csv_text = "x,y,label\n1,2,normal\n3,4,anomaly\n5,6,normal\n"
        loader = CSVDatasetLoader(
            label_column="label",
            label_map={"normal": DataLabel.NORMAL, "anomaly": DataLabel.ANOMALY},
        )
        ds = loader.load_string(csv_text)
        assert ds.feature_names == ["x", "y"]
        assert ds.points[0].label == DataLabel.NORMAL
        assert ds.points[1].label == DataLabel.ANOMALY

    def test_non_numeric_defaults_to_zero(self):
        csv_text = "a,b\nfoo,1.0\n2.0,bar\n"
        loader = CSVDatasetLoader()
        ds = loader.load_string(csv_text)
        assert ds.points[0].features == [0.0, 1.0]
        assert ds.points[1].features == [2.0, 0.0]

    def test_file_not_found(self):
        loader = CSVDatasetLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_file("/nonexistent/path.csv")


# ===================================================================
# Datasets — feature utilities
# ===================================================================


class TestFeatureUtilities:
    def test_normalise_features(self):
        ds = Dataset(name="test", points=[
            DataPoint(features=[0.0, 10.0]),
            DataPoint(features=[5.0, 20.0]),
            DataPoint(features=[10.0, 30.0]),
        ])
        normed = normalise_features(ds)
        assert normed.points[0].features == [0.0, 0.0]
        assert normed.points[2].features == [1.0, 1.0]
        assert normed.points[1].features == [0.5, 0.5]

    def test_normalise_single_value(self):
        ds = Dataset(name="test", points=[
            DataPoint(features=[5.0, 5.0]),
            DataPoint(features=[5.0, 5.0]),
        ])
        normed = normalise_features(ds)
        assert normed.points[0].features == [0.0, 0.0]

    def test_compute_statistics(self):
        ds = Dataset(
            name="test",
            feature_names=["x", "y"],
            points=[
                DataPoint(features=[1.0, 10.0]),
                DataPoint(features=[3.0, 20.0]),
                DataPoint(features=[5.0, 30.0]),
            ],
        )
        stats = compute_statistics(ds)
        assert "x" in stats
        assert abs(stats["x"]["mean"] - 3.0) < 0.01
        assert stats["x"]["min"] == 1.0
        assert stats["x"]["max"] == 5.0

    def test_dataset_split(self):
        pts = [DataPoint(features=[float(i)]) for i in range(100)]
        ds = Dataset(name="test", points=pts)
        train, test = ds.split(train_ratio=0.7, seed=99)
        assert len(train) == 70
        assert len(test) == 30


# ===================================================================
# Node framework
# ===================================================================


class TestNodeLifecycle:
    @pytest.mark.asyncio
    async def test_node_start_stop(self):
        bus = EventBus()
        node = AnomalyDetectionNode(bus)
        assert node.state == NodeState.CREATED
        await node.start()
        assert node.state == NodeState.RUNNING
        await node.stop()
        assert node.state == NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_node_receives_events(self):
        bus = EventBus()
        node = AnomalyDetectionNode(bus)
        await node.start()
        # Publish a metric event that the node subscribes to
        await bus.publish(Event(topic="sensor.metrics", data={"features": [5.0, 5.0]}))
        assert node._messages_in == 1
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_publishes_results(self):
        bus = EventBus()
        results = []

        async def capture(event: Event) -> None:
            results.append(event)

        bus.subscribe("ai.anomaly_scored", capture)
        node = AnomalyDetectionNode(bus)
        await node.start()
        # Send metric data
        await bus.publish(Event(topic="sensor.metrics", data={"features": [5.0, 5.0]}))
        assert len(results) == 1
        assert "score" in results[0].data["message"].payload
        await node.stop()

    @pytest.mark.asyncio
    async def test_node_health(self):
        bus = EventBus()
        node = ForecastNode(bus)
        await node.start()
        h = node.health()
        assert h["node"] == "forecast_node"
        assert h["state"] == "running"
        assert h["messages_in"] == 0
        await node.stop()


class TestNodeGraph:
    @pytest.mark.asyncio
    async def test_create_default_graph(self):
        bus = EventBus()
        graph = NodeGraph.create_default(bus)
        assert len(graph.node_names) == 4
        assert "anomaly_detection_node" in graph.node_names
        assert "forecast_node" in graph.node_names
        assert "audit_analysis_node" in graph.node_names
        assert "task_recommendation_node" in graph.node_names

    @pytest.mark.asyncio
    async def test_start_stop_all(self):
        bus = EventBus()
        graph = NodeGraph.create_default(bus)
        await graph.start_all()
        health = graph.health_all()
        assert all(h["state"] == "running" for h in health)
        await graph.stop_all()
        health = graph.health_all()
        assert all(h["state"] == "stopped" for h in health)

    @pytest.mark.asyncio
    async def test_topology(self):
        bus = EventBus()
        graph = NodeGraph.create_default(bus)
        topo = graph.topology()
        assert "anomaly_detection_node" in topo
        assert "sensor.metrics" in topo["anomaly_detection_node"]["inputs"]
        assert "ai.anomaly_scored" in topo["anomaly_detection_node"]["outputs"]

    @pytest.mark.asyncio
    async def test_duplicate_node_raises(self):
        bus = EventBus()
        graph = NodeGraph(bus)
        graph.add_node(AnomalyDetectionNode(bus))
        with pytest.raises(ValueError):
            graph.add_node(AnomalyDetectionNode(bus))

    @pytest.mark.asyncio
    async def test_end_to_end_data_flow(self):
        """Publish sensor data → anomaly node scores → downstream receives."""
        bus = EventBus()
        scored_events = []

        async def capture(event: Event) -> None:
            scored_events.append(event)

        bus.subscribe("ai.anomaly_scored", capture)
        graph = NodeGraph(bus)
        graph.add_node(AnomalyDetectionNode(bus))
        await graph.start_all()

        # Simulate sensor publishing metric features
        await bus.publish(Event(topic="sensor.metrics", data={"features": [3.0, 3.0]}))
        assert len(scored_events) == 1
        payload = scored_events[0].data["message"].payload
        assert "score" in payload
        assert "is_anomaly" in payload

        await graph.stop_all()

    @pytest.mark.asyncio
    async def test_forecast_node_processes_series(self):
        bus = EventBus()
        forecast_events = []

        async def capture(event: Event) -> None:
            forecast_events.append(event)

        bus.subscribe("ai.forecast_ready", capture)
        node = ForecastNode(bus)
        await node.start()

        import random
        rng = random.Random(7)
        series = [10 + 0.5 * i + rng.gauss(0, 1) for i in range(80)]
        await bus.publish(Event(topic="sensor.timeseries", data={"series": series, "steps": 5}))
        assert len(forecast_events) == 1
        pts = forecast_events[0].data["message"].payload["points"]
        assert len(pts) == 5
        await node.stop()


# ===================================================================
# Training pipeline
# ===================================================================


class TestModelRegistry:
    def test_register_and_latest(self):
        reg = ModelRegistry()
        report = TrainingReport(model_name="test", dataset_name="ds",
                                train_samples=100, test_samples=20, duration_secs=1.0)
        snap = ModelSnapshot(name="test", version=1,
                             trained_at=datetime.now(timezone.utc), report=report)
        reg.register(snap)
        assert reg.latest("test") is snap
        assert reg.latest("nonexistent") is None

    def test_multiple_versions(self):
        reg = ModelRegistry()
        now = datetime.now(timezone.utc)
        for v in range(1, 4):
            report = TrainingReport(model_name="m", dataset_name="d",
                                    train_samples=100, test_samples=20, duration_secs=0.5)
            reg.register(ModelSnapshot(name="m", version=v, trained_at=now, report=report))
        assert len(reg.all_versions("m")) == 3
        assert reg.latest("m").version == 3


class TestTrainingPipeline:
    def test_train_anomaly_detector(self):
        from network_guardian.ai.anomaly import EnsembleDetector, IsolationForest, OneClassSVM
        gen = NetworkTrafficGenerator(seed=42)
        ds = gen.generate(n_normal=200, n_anomaly=20, n_attack=10, n_scan=10)
        ensemble = EnsembleDetector()
        ensemble.add_detector(IsolationForest(n_trees=30, seed=42))
        ensemble.add_detector(OneClassSVM(nu=0.15, seed=42))
        pipeline = TrainingPipeline()
        report = pipeline.train_anomaly_detector(ensemble, ds)
        assert report.model_name == "ensemble_detector"
        assert "accuracy" in report.metrics
        assert "f1" in report.metrics
        assert report.metrics["accuracy"] > 0

    def test_train_forecaster(self):
        from network_guardian.ai.forecasting import ARIMAForecaster
        gen = MetricTimeSeriesGenerator(seed=42)
        _, series = gen.generate(length=200, period=24)
        pipeline = TrainingPipeline()
        report = pipeline.train_forecaster(ARIMAForecaster(p=3, d=1, q=1), series, holdout=20)
        assert "mae" in report.metrics
        assert "rmse" in report.metrics
        assert "coverage" in report.metrics

    def test_full_anomaly_pipeline(self):
        pipeline = TrainingPipeline()
        report = pipeline.run_full_anomaly_pipeline(
            n_normal=100, n_anomaly=15, n_attack=10, n_scan=10, seed=99,
        )
        assert report.accuracy is not None
        assert report.f1_score is not None
        # Should be registered in the model registry
        assert pipeline.registry.latest("ensemble_detector") is not None

    def test_full_forecast_pipeline_arima(self):
        pipeline = TrainingPipeline()
        report = pipeline.run_full_forecast_pipeline(
            length=200, period=24, method="arima", holdout=10,
        )
        assert report.metrics["mae"] >= 0

    def test_full_forecast_pipeline_seasonal(self):
        pipeline = TrainingPipeline()
        report = pipeline.run_full_forecast_pipeline(
            length=200, period=24, method="seasonal", holdout=10,
        )
        assert report.metrics["mae"] >= 0

    def test_full_forecast_pipeline_holt_winters(self):
        pipeline = TrainingPipeline()
        report = pipeline.run_full_forecast_pipeline(
            length=200, period=12, method="holt_winters", holdout=10,
        )
        assert report.metrics["mae"] >= 0

    def test_insufficient_data_forecast(self):
        from network_guardian.ai.forecasting import ARIMAForecaster
        pipeline = TrainingPipeline()
        report = pipeline.train_forecaster(ARIMAForecaster(), [1.0, 2.0, 3.0], holdout=10)
        assert "error" in report.metrics

    def test_report_summary(self):
        report = TrainingReport(
            model_name="test_model", dataset_name="test_ds",
            train_samples=80, test_samples=20, duration_secs=0.5,
            metrics={"accuracy": 0.95, "f1": 0.90},
        )
        text = report.summary()
        assert "test_model" in text
        assert "accuracy" in text


# ===================================================================
# Engine integration
# ===================================================================


class TestEngineIntegration:
    @pytest.mark.asyncio
    async def test_engine_node_graph_property(self):
        engine = Engine()
        graph = engine.node_graph
        assert len(graph.node_names) == 4

    @pytest.mark.asyncio
    async def test_engine_training_property(self):
        engine = Engine()
        pipeline = engine.training
        assert pipeline is engine.training  # cached

    @pytest.mark.asyncio
    async def test_engine_start_stop_with_nodes(self):
        engine = Engine()
        _ = engine.node_graph  # force creation so start_all runs
        await engine.start()
        assert engine.is_running
        health = engine.node_graph.health_all()
        assert all(h["state"] == "running" for h in health)
        await engine.stop()
        assert not engine.is_running
        health = engine.node_graph.health_all()
        assert all(h["state"] == "stopped" for h in health)

    @pytest.mark.asyncio
    async def test_engine_train_anomaly(self):
        engine = Engine()
        report = engine.training.run_full_anomaly_pipeline(
            n_normal=100, n_anomaly=10, n_attack=5, n_scan=5,
        )
        assert report.accuracy is not None
