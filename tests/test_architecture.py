"""Tests for the AI engine, NLP, sensors, dashboard, and plugin system."""

import pytest

from network_guardian.config import Config
from network_guardian.core.events import EventBus
from network_guardian.core.plugins import Plugin, PluginRegistry
from network_guardian.ai import AIEngine, AnomalyClassifier, PatternRecogniser, PredictionType
from network_guardian.ai.nlp import NLPEngine
from network_guardian.sensors import PingSensor, PortScanner, SystemMetricsSensor, SensorRegistry


# ---------------------------------------------------------------------------
# Plugin system
# ---------------------------------------------------------------------------


class DummyPlugin(Plugin):
    name = "dummy"

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class TestPluginRegistry:
    def test_register_and_list(self):
        config = Config()
        bus = EventBus()
        registry = PluginRegistry()
        plugin = DummyPlugin(config, bus)
        registry.register(plugin)
        assert "dummy" in registry.names

    def test_duplicate_raises(self):
        config = Config()
        bus = EventBus()
        registry = PluginRegistry()
        plugin = DummyPlugin(config, bus)
        registry.register(plugin)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(plugin)

    @pytest.mark.asyncio
    async def test_start_stop_all(self):
        config = Config()
        bus = EventBus()
        registry = PluginRegistry()
        registry.register(DummyPlugin(config, bus))
        await registry.start_all()
        await registry.stop_all()

    @pytest.mark.asyncio
    async def test_health_check(self):
        config = Config()
        bus = EventBus()
        registry = PluginRegistry()
        registry.register(DummyPlugin(config, bus))
        results = registry.health_check_all()
        assert len(results) == 1
        assert results[0]["status"] == "ok"


# ---------------------------------------------------------------------------
# AI Engine
# ---------------------------------------------------------------------------


class TestAIEngine:
    @pytest.mark.asyncio
    async def test_classify_anomaly_normal(self):
        config = Config()
        bus = EventBus()
        ai = AIEngine(config, bus)
        pred = await ai.classify_anomaly({"metric_name": "cpu", "value": 50.0, "z_score": 0.5})
        assert pred.label == "normal"
        assert pred.prediction_type == PredictionType.ANOMALY

    @pytest.mark.asyncio
    async def test_classify_anomaly_detected(self):
        config = Config()
        bus = EventBus()
        ai = AIEngine(config, bus)
        pred = await ai.classify_anomaly({"metric_name": "cpu", "value": 99.0, "z_score": 5.0})
        assert pred.label == "anomaly"

    @pytest.mark.asyncio
    async def test_generate_recommendations_empty(self):
        config = Config()
        bus = EventBus()
        ai = AIEngine(config, bus)
        recs = await ai.generate_recommendations([], [])
        assert recs == []

    @pytest.mark.asyncio
    async def test_generate_recommendations_with_findings(self):
        from network_guardian.models.network import Finding, Severity

        config = Config()
        bus = EventBus()
        ai = AIEngine(config, bus)

        findings = [
            Finding(title="Open SSH", description="Port 22 open", severity=Severity.HIGH, host="10.0.0.1"),
            Finding(title="Weak cipher", description="TLS 1.0", severity=Severity.MEDIUM),
        ]
        recs = await ai.generate_recommendations(findings, [])
        assert len(recs) == 2  # one critical group, one medium group

    def test_model_registration(self):
        config = Config()
        bus = EventBus()
        ai = AIEngine(config, bus)
        assert "anomaly_classifier" in ai.model_names
        assert "pattern_recogniser" in ai.model_names


class TestAnomalyClassifier:
    @pytest.mark.asyncio
    async def test_train_and_predict(self):
        model = AnomalyClassifier()
        result = await model.train([{"metric_name": "cpu", "threshold": 3.0}])
        assert result["status"] == "trained"

        pred = await model.predict({"metric_name": "cpu", "value": 95, "z_score": 4.0})
        assert pred.label == "anomaly"


class TestPatternRecogniser:
    @pytest.mark.asyncio
    async def test_predict_unknown(self):
        model = PatternRecogniser()
        pred = await model.predict({"src_ip": "10.0.0.1", "dst_port": 80})
        assert pred.label == "unknown"


# ---------------------------------------------------------------------------
# NLP Engine
# ---------------------------------------------------------------------------


class TestNLPEngine:
    def test_parse_intent_audit(self):
        config = Config()
        bus = EventBus()
        nlp = NLPEngine(config, bus)
        intent = nlp.parse_intent("scan 192.168.1.0/24 for vulnerabilities")
        assert intent.action == "audit"
        assert "192.168.1.0/24" in intent.targets

    def test_parse_intent_explore(self):
        config = Config()
        bus = EventBus()
        nlp = NLPEngine(config, bus)
        intent = nlp.parse_intent("discover hosts on 10.0.0.0/8")
        assert intent.action == "explore"

    def test_parse_intent_unknown(self):
        config = Config()
        bus = EventBus()
        nlp = NLPEngine(config, bus)
        intent = nlp.parse_intent("what is the meaning of life")
        assert intent.action == "unknown"

    def test_analyse_logs_matches(self):
        config = Config()
        bus = EventBus()
        nlp = NLPEngine(config, bus)
        logs = [
            "2026-04-10 INFO all good",
            "2026-04-10 ERROR authentication failed for user admin",
            "2026-04-10 WARN connection refused on port 443",
        ]
        matches = nlp.analyse_logs(logs)
        assert len(matches) == 2
        assert matches[0]["pattern"] == "auth_failure"
        assert matches[1]["pattern"] == "connection_refused"

    def test_analyse_logs_no_matches(self):
        config = Config()
        bus = EventBus()
        nlp = NLPEngine(config, bus)
        assert nlp.analyse_logs(["everything is fine"]) == []

    def test_summarise_findings(self):
        config = Config()
        bus = EventBus()
        nlp = NLPEngine(config, bus)
        summary = nlp.summarise_findings([])
        assert "No issues" in summary

        summary = nlp.summarise_findings([{"title": "Test", "severity": "high", "description": "desc"}])
        assert "1 issue" in summary


# ---------------------------------------------------------------------------
# Sensors
# ---------------------------------------------------------------------------


class TestSensorRegistry:
    def test_register_and_list(self):
        config = Config()
        bus = EventBus()
        registry = SensorRegistry()
        registry.register(SystemMetricsSensor(config, bus))
        assert "system_metrics" in registry.names

    @pytest.mark.asyncio
    async def test_system_metrics_collect(self):
        config = Config()
        bus = EventBus()
        sensor = SystemMetricsSensor(config, bus)
        reading = await sensor.collect()
        assert reading.sensor_name == "system_metrics"
        assert "disk_total_gb" in reading.data or "cpu_load_1m" in reading.data


# ---------------------------------------------------------------------------
# Engine integration with new subsystems
# ---------------------------------------------------------------------------


class TestEngineArchitecture:
    @pytest.mark.asyncio
    async def test_engine_has_ai(self):
        from network_guardian.core.engine import Engine
        engine = Engine()
        assert "anomaly_classifier" in engine.ai.model_names

    @pytest.mark.asyncio
    async def test_engine_has_nlp(self):
        from network_guardian.core.engine import Engine
        engine = Engine()
        intent = engine.nlp.parse_intent("audit 10.0.0.1")
        assert intent.action == "audit"

    @pytest.mark.asyncio
    async def test_engine_has_sensors(self):
        from network_guardian.core.engine import Engine
        engine = Engine()
        assert "ping" in engine.sensors.names
        assert "port_scanner" in engine.sensors.names
        assert "system_metrics" in engine.sensors.names

    @pytest.mark.asyncio
    async def test_engine_has_dashboard(self):
        from network_guardian.core.engine import Engine
        engine = Engine()
        assert engine.dashboard is not None
        assert engine.dashboard.port == 8080
