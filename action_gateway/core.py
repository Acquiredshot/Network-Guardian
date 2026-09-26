"""Action Gateway core — public API for executing security actions.


This module exposes the interfaces for queuing, executing, and
tracking security actions across the available connectors.
"""

from __future__ import annotations

from typing import Any


class Action:
    """A single security action to be executed.

    Carries the intent (what to do), target (what it applies to),
    and any parameters required by the underlying connector.
    """

    def __init__(
        self,
        *,
        action_id: str,
        action_type: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        """Initialise an action.

        Args:
            action_id: Unique identifier for this action instance.
            action_type: Type of action — ``isolate_host``, ``disable_account``,
                ``block_indicator``, ``quarantine_file``, etc.
            target: The object the action applies to (host id, account, indicator, file).
            parameters: Optional connector-specific parameters.
        """
        self.action_id = action_id
        self.action_type = action_type
        self.target = target
        self.parameters = parameters or {}


class ActionConnector:
    """A pluggable executor for a specific action type or target system.

    Connectors translate Action objects into concrete operations on
    the target system (API call, CLI command, infrastructure change).
    """

    def execute(self, *, action: Action) -> dict[str, Any]:
        """Execute the given action.

        Args:
            action: The Action to execute.

        Returns:
            Result dict with at minimum ``status`` (``success``, ``failure``,
            ``partial``) and any connector-specific output.
        """
        pass

    def action_types(self) -> list[str]:
        """Return the action types this connector can handle.

        Returns:
            List of action type strings.
        """
        pass


class ActionGateway:
    """Central action dispatch, tracking, and audit surface.

    Receives decisions from the Policy Engine, resolves the appropriate
    connector, executes the action, and records the outcome for audit.
    """

    def register_connector(self, *, connector: ActionConnector) -> None:
        """Register a connector with the gateway.

        Args:
            connector: The ActionConnector to make available.
        """
        pass

    def execute(self, *, action: Action) -> dict[str, Any]:
        """Dispatch and execute an action through the appropriate connector.

        Args:
            action: The Action to execute.

        Returns:
            Execution result dict.
        """
        pass

    def status(self, *, action_id: str) -> dict[str, Any]:
        """Query the current status of an action.

        Args:
            action_id: The action to look up.

        Returns:
            Status dict with ``action_id``, ``status``, ``started_at``,
            ``completed_at``, and ``result`` keys when available.
        """
        pass

    def history(self, *, action_type: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent execution history, optionally filtered by type.

        Args:
            action_type: Optional action type filter.
            limit: Maximum number of records to return.

        Returns:
            List of execution history dicts.
        """
        pass
