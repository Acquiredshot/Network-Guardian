# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Action Gateway — execution layer.

Executes approved response actions in the customer environment.
Provides an abstraction layer so that actions (isolate host, block IP,
revoke token, etc.) can be executed via different backends (NG engine,
cloud APIs, on-prem agents).

Execution pipeline:
    Policy-approved action ──► ActionGateway.execute() ──► customer environment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from ai_security_orchestrator.response import ResponseActionType


class ExecutionStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    NOT_FOUND = "not_found"
    DENIED = "denied"


@dataclass
class ExecutionResult:
    """Result of executing a single action."""

    action_id: str
    action_type: str
    target_id: str
    status: ExecutionStatus
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    executed_at: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_id": self.target_id,
            "status": self.status.value,
            "has_details": len(self.details) > 0,
        }


from ai_security_orchestrator.response import ResponseActionType


class ActionExecutor:
    """Base action executor — implement per action type + backend."""

    action_type: str = "base"

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        raise NotImplementedError


class ActionGateway:
    """Phase 1 action gateway — dispatches actions to registered executors."""

    def __init__(self) -> None:
        self._executors: dict[str, ActionExecutor] = {}
        self._results: list[ExecutionResult] = []
        self._audit_log: list[dict[str, Any]] = []

    def register_executor(self, executor: ActionExecutor) -> None:
        self._executors[executor.action_type] = executor

    def execute(
        self, action_type: str, target_id: str, parameters: dict[str, Any] | None = None
    ) -> ExecutionResult:
        """Execute a single action via the registered executor for its type."""
        if parameters is None:
            parameters = {}

        executor = self._executors.get(action_type)
        if executor is None:
            result = ExecutionResult(
                action_id=f"exec-{action_type}-{target_id}",
                action_type=action_type,
                target_id=target_id,
                status=ExecutionStatus.NOT_FOUND,
                message=f"No executor registered for action type '{action_type}'",
            )
            self._results.append(result)
            self._audit_log.append({"action_type": action_type, "target_id": target_id, "status": "not_found"})
            return result

        result = executor.execute(target_id, parameters)
        result.action_id = f"exec-{action_type}-{target_id}"
        self._results.append(result)
        self._audit_log.append({
            "action_type": action_type,
            "target_id": target_id,
            "status": result.status.value,
        })
        return result

    def get_results(self, status: ExecutionStatus | None = None) -> list[ExecutionResult]:
        if status is None:
            return list(self._results)
        return [r for r in self._results if r.status == status]

    def get_audit_log(self) -> list[dict[str, Any]]:
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Built-in phase 1 executors
    # ------------------------------------------------------------------

    def register_alert_only_executor(self, notify_fn: Callable[[dict[str, Any]], None] | None = None) -> None:
        """Register an alert-only executor that notifies instead of mutating."""
        self._executors[ResponseActionType.ALERT_ONLY.value] = _AlertOnlyExecutor(notify_fn)

    def register_block_ip_executor(self, block_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        """Register a block-IP executor (integrates with NG engine in production)."""
        self._executors[ResponseActionType.BLOCK_IP.value] = _BlockIPExecutor(block_fn)

    def register_isolate_host_executor(self, isolate_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        """Register an isolate-host executor (integrates with NG engine in production)."""
        self._executors[ResponseActionType.ISOLATE_HOST.value] = _IsolateHostExecutor(isolate_fn)

    def register_revoke_token_executor(self, revoke_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        """Register a revoke-token executor (integrates with Pakshield access control)."""
        self._executors[ResponseActionType.REVOKE_TOKEN.value] = _RevokeTokenExecutor(revoke_fn)

    def register_terminate_process_executor(self, term_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        """Register a terminate-process executor (integrates with host agent)."""
        self._executors[ResponseActionType.TERMINATE_PROCESS.value] = _TerminateProcessExecutor(term_fn)

    def register_force_password_reset_executor(self, reset_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        """Register a force-password-reset executor (integrates with Pakshield identity)."""
        self._executors[ResponseActionType.FORCE_PASSWORD_RESET.value] = _ForcePasswordResetExecutor(reset_fn)


# ---------------------------------------------------------------------------
# Built-in phase 1 executor implementations
# ---------------------------------------------------------------------------

class _AlertOnlyExecutor(ActionExecutor):
    action_type = "alert_only"

    def __init__(self, notify_fn: Callable[[dict[str, Any]], None] | None = None) -> None:
        self._notify_fn = notify_fn

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        msg = parameters.get("message", f"Alert: action '{self.action_type}' for {target_id}")
        if self._notify_fn:
            self._notify_fn({"target_id": target_id, "message": msg})
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Alert delivered for {target_id}: {msg}",
        )


class _BlockIPExecutor(ActionExecutor):
    action_type = "block_ip"

    def __init__(self, block_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        self._block_fn = block_fn

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        if self._block_fn:
            return self._block_fn(target_id)
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Block IP action recorded for {target_id} (no backend — phase 1 stub)",
            details={"action": "block_ip", "target": target_id},
        )


class _IsolateHostExecutor(ActionExecutor):
    action_type = "isolate_host"

    def __init__(self, isolate_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        self._isolate_fn = isolate_fn

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        if self._isolate_fn:
            return self._isolate_fn(target_id)
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Isolate host action recorded for {target_id} (no backend — phase 1 stub)",
            details={"action": "isolate_host", "target": target_id},
        )


class _RevokeTokenExecutor(ActionExecutor):
    action_type = "revoke_token"

    def __init__(self, revoke_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        self._revoke_fn = revoke_fn

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        if self._revoke_fn:
            return self._revoke_fn(target_id)
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Revoke token action recorded for {target_id} (no backend — phase 1 stub)",
            details={"action": "revoke_token", "target": target_id},
        )


class _TerminateProcessExecutor(ActionExecutor):
    action_type = "terminate_process"

    def __init__(self, term_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        self._term_fn = term_fn

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        if self._term_fn:
            return self._term_fn(target_id)
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Terminate process action recorded for {target_id} (no backend — phase 1 stub)",
            details={"action": "terminate_process", "target": target_id},
        )


class _ForcePasswordResetExecutor(ActionExecutor):
    action_type = "force_password_reset"

    def __init__(self, reset_fn: Callable[[str], ExecutionResult] | None = None) -> None:
        self._reset_fn = reset_fn

    def execute(self, target_id: str, parameters: dict[str, Any]) -> ExecutionResult:
        if self._reset_fn:
            return self._reset_fn(target_id)
        return ExecutionResult(
            action_id="",
            action_type=self.action_type,
            target_id=target_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Force password reset action recorded for {target_id} (no backend — phase 1 stub)",
            details={"action": "force_password_reset", "target": target_id},
        )
