# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Plugin system for Network Guardian.

Provides a base class and registry for dynamically loading subsystem plugins
(sensors, AI models, dashboard components, etc.).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import EventBus

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.core.plugins")


class Plugin(ABC):
    """Base class for all Network Guardian plugins."""

    name: str = "unnamed"

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus

    @abstractmethod
    async def start(self) -> None:
        """Initialise and start the plugin."""

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully shut down the plugin."""

    def health_check(self) -> dict[str, Any]:
        """Return plugin health status. Override for custom checks."""
        return {"plugin": self.name, "status": "ok"}


class PluginRegistry:
    """Manages discovery and lifecycle of plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' is already registered")
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Plugin:
        return self._plugins[name]

    async def start_all(self) -> None:
        for plugin in self._plugins.values():
            await plugin.start()

    async def stop_all(self) -> None:
        for plugin in self._plugins.values():
            await plugin.stop()

    def health_check_all(self) -> list[dict[str, Any]]:
        return [p.health_check() for p in self._plugins.values()]

    @property
    def names(self) -> list[str]:
        return list(self._plugins.keys())
