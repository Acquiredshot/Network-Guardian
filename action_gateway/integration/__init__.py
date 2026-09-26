# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Action Gateway — integration layer.

Provides backend integrations for the Action Gateway execution layer:
- Network Guardian engine integration (block IP, isolate host, terminate process)
- Pakshield identity integration (revoke token, force password reset)
- Cloud/tenant API integration stubs (phase 2+)
"""

from __future__ import annotations

from typing import Any

from action_gateway.execution import (
    ActionExecutor,
    ActionGateway,
    ExecutionResult,
    ExecutionStatus,
)


class NGBackendExecutor(ActionExecutor):
    """Action executor that delegates to the Network Guardian engine.

    Phase 1 stub — wires into NG engine's block-IP / isolate-host / terminate
    APIs in production. For now, records the intended action and returns success.
    """

    action_type = "ng_backend"

    def __init__(self, ng_engine: Any | None = None) -> None:
        self._ng_engine = ng_engine

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        action = parameters.get("action", "block_ip")
        if self._ng_engine is not None:
            # Production: call ng_engine.block_ip(target_id) etc.
            pass
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"NG backend action '{action}' recorded for {target_id} (phase 1 stub)",
            details={"backend": "network_guardian", "action": action, "target": target_id},
        )


class PakshieldBackendExecutor(ActionExecutor):
    """Action executor that delegates to the Pakshield identity/access layer.

    Phase 1 stub — wires into Pakshield's revoke-token / force-reset APIs
    in production.
    """

    action_type = "pakshield_backend"

    def __init__(self, pakshield: Any | None = None) -> None:
        self._pakshield = pakshield

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        action = parameters.get("action", "revoke_token")
        if self._pakshield is not None:
            # Production: call pakshield.revoke_token(target_id) etc.
            pass
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Pakshield backend action '{action}' recorded for {target_id} (phase 1 stub)",
            details={"backend": "pakshield", "action": action, "target": target_id},
        )


class ActionGatewayIntegration:
    """Top-level integration facade — registers all backend executors."""

    def __init__(self, gateway: ActionGateway | None = None) -> None:
        self._gateway = gateway or ActionGateway()
        self._register_all()

    def _register_all(self) -> None:
        self._gateway.register_executor(NGBackendExecutor())
        self._gateway.register_executor(PakshieldBackendExecutor())
        # Also register the built-in executors from the execution module
        self._gateway.register_alert_only_executor()
        self._gateway.register_block_ip_executor()
        self._gateway.register_isolate_host_executor()
        self._gateway.register_revoke_token_executor()
        self._gateway.register_terminate_process_executor()
        self._gateway.register_force_password_reset_executor()

    @property
    def gateway(self) -> ActionGateway:
        return self._gateway

    def execute(self, action_type: str, target_id: str, parameters: dict[str, Any] | None = None) -> ExecutionResult:
        return self._gateway.execute(action_type, target_id, parameters)

    def get_results(self, status: ExecutionStatus | None = None) -> list[ExecutionResult]:
        return self._gateway.get_results(status)

    def get_audit_log(self) -> list[dict[str, Any]]:
        return self._gateway.get_audit_log()
