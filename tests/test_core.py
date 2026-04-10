"""Basic smoke tests for core components."""

import pytest

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.core.events import Event, EventBus


class TestConfig:
    def test_defaults(self):
        cfg = Config()
        assert cfg.log_level == "INFO"
        assert cfg.scan.timeout == 5.0
        assert cfg.monitor.poll_interval == 30.0

    def test_load_without_file(self):
        cfg = Config.load(None)
        assert cfg.log_level == "INFO"


class TestEventBus:
    @pytest.mark.asyncio
    async def test_publish_subscribe(self):
        bus = EventBus()
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("test.topic", handler)
        await bus.publish(Event(topic="test.topic", data={"key": "value"}))

        assert len(received) == 1
        assert received[0].data["key"] == "value"

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        bus = EventBus()
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("test.topic", handler)
        bus.unsubscribe("test.topic", handler)
        await bus.publish(Event(topic="test.topic"))

        assert len(received) == 0


class TestEngine:
    @pytest.mark.asyncio
    async def test_start_stop(self):
        engine = Engine()
        await engine.start()
        assert engine.is_running
        await engine.stop()
        assert not engine.is_running
