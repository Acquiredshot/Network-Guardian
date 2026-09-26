"""Firewall API connector back-end for the Action Gateway."""
from __future__ import annotations

from typing import Any

from action_gateway.execution import ActionExecutor, ExecutionResult, ExecutionStatus


class FirewallApiExecutor(ActionExecutor):
    """Executes firewall actions via the NG engine's firewall API.

    Phase 1: stub — records intended actions.
    Phase 2: connects to Network Guardian's firewall/IPS control plane.
    """

    action_type = "firewall_api"

    def __init__(self, ng_engine: Any | None = None) -> None:
        self._ng_engine = ng_engine

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        action = parameters.get("action", "block_ip")
        duration = parameters.get("duration_seconds", 3600)

        if self._ng_engine is not None:
            # Production path: ng_engine.firewall.block_ip(target_id, duration)
            pass

        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Firewall API action '{action}' recorded for {target_id} (phase 1 stub)",
            details={
                "backend": "network_guardian.firewall",
                "action": action,
                "target": target_id,
                "duration_seconds": duration,
            },
        )
