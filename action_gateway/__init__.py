# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Action Gateway — top-level facade.

Provides a unified entry point for executing response actions across
all registered backends (NG engine, Pakshield identity, built-in stubs).
"""

from __future__ import annotations

from typing import Any

from action_gateway.integration import ActionGatewayIntegration, ActionGateway


class ActionGatewayFacade:
    """Unified action execution facade for the Wolf-Pak platform."""

    def __init__(self) -> None:
        self._integration = ActionGatewayIntegration()
        self._gateways: dict[str, ActionGateway] = {
            "default": self._integration.gateway,
        }

    def register_gateway(self, name: str, gateway: ActionGateway) -> None:
        self._gateways[name] = gateway

    def execute(
        self,
        action_type: str,
        target_id: str,
        parameters: dict[str, Any] | None = None,
        gateway: str = "default",
    ) -> ExecutionResult:
        gw = self._gateways.get(gateway, self._gateways["default"])
        return gw.execute(action_type, target_id, parameters)

    def execute_response_actions(
        self, actions: list[dict[str, Any]], gateway: str = "default"
    ) -> list[ExecutionResult]:
        """Execute a list of response actions (from a ResponsePlan)."""
        results: list[ExecutionResult] = []
        for action in actions:
            result = self.execute(
                action_type=action.get("action_type", ""),
                target_id=action.get("target_id", ""),
                parameters=action.get("parameters", {}),
                gateway=gateway,
            )
            results.append(result)
        return results

    def get_all_results(self, status: ExecutionStatus | None = None) -> list[ExecutionResult]:
        results: list[ExecutionResult] = []
        for gw in self._gateways.values():
            results.extend(gw.get_results(status))
        return results

    @property
    def default_gateway(self) -> ActionGateway:
        return self._gateways["default"]


# ---------------------------------------------------------------------------
# Convenience re-exports
# ---------------------------------------------------------------------------

from action_gateway.execution import (
    ActionExecutor,
    ActionGateway,
    ExecutionResult,
    ExecutionStatus,
    ResponseActionType,
)
from action_gateway.connectors import FirewallApiExecutor


__all__ = [
    "ActionGatewayFacade",
    "ActionGateway",
    "ActionExecutor",
    "ExecutionResult",
    "ExecutionStatus",
    "ResponseActionType",
    "FirewallApiExecutor",
]

__version__ = "0.1.0"
