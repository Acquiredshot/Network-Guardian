"""
System Monitor — real-time monitoring and anomaly detection.

Collects metrics, tracks baselines, and fires alerts when anomalies occur.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import statistics
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from network_guardian.core.events import Event, EventBus
from network_guardian.models.network import Metric

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.monitor")


class Monitor:
    """Collects metrics and detects anomalies via statistical thresholds."""

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus

        # Rolling window of recent values per metric name
        self._history: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._running = False
        self._poll_task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Begin the monitoring loop."""
        self._running = True
        self._poll_task = asyncio.create_task(self._poll_loop())
        logger.info("Monitor started (interval=%.1fs).", self.config.monitor.poll_interval)

    async def stop(self) -> None:
        """Stop the monitoring loop."""
        self._running = False
        if self._poll_task is not None:
            self._poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._poll_task
        logger.info("Monitor stopped.")

    async def record(self, metric: Metric) -> None:
        """Record a metric and check for anomalies."""
        self._history[metric.name].append(metric.value)
        if self._is_anomaly(metric.name, metric.value):
            logger.warning("Anomaly detected: %s = %.2f", metric.name, metric.value)
            await self.event_bus.publish(Event(
                topic="monitor.anomaly",
                data={"metric": metric},
            ))

    def _is_anomaly(self, name: str, value: float) -> bool:
        """Check if value deviates from historical mean by more than threshold * stdev."""
        history = self._history[name]
        if len(history) < 10:
            return False
        mean = statistics.mean(history)
        stdev = statistics.stdev(history)
        if stdev == 0:
            return False
        z_score = abs(value - mean) / stdev
        return z_score > self.config.monitor.anomaly_threshold

    async def _poll_loop(self) -> None:
        """Placeholder polling loop — collectors will be plugged in."""
        while self._running:
            # Real implementation: call registered collectors here
            await asyncio.sleep(self.config.monitor.poll_interval)
