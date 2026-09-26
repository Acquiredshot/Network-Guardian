"""AI Orchestrator public API — detection, investigation, response workflows.


This module is the entry point for consumers that want to run,
coordinate, or monitor the AI-driven security pipelines.
"""

from __future__ import annotations

from typing import Any


class DetectionPipeline:
    """Run detection logic over raw signals and emit structured detections.

    Consumes raw sensor output, applies models and heuristics, and
    publishes DetectionEvents into the Event Fabric.
    """

    def run(self, *, signal_batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process a batch of raw signals and return detections.

        Args:
            signal_batch: Raw signal dicts from sensors.

        Returns:
            List of detection result dicts ready for Event Fabric publication.
        """
        pass


class InvestigationSession:
    """Manage a single incident investigation lifecycle.

    Drives data collection, hypothesis formation, and evidence
    gathering against a trigger event.
    """

    def start(self, *, trigger_event: dict[str, Any]) -> str:
        """Begin an investigation from a trigger event.

        Args:
            trigger_event: The detection or alert that started the investigation.

        Returns:
            Investigation session identifier.
        """
        pass

    def step(self, *, session_id: str) -> dict[str, Any]:
        """Advance the investigation by one reasoning step.

        Args:
            session_id: The investigation to advance.

        Returns:
            Update dict describing what the step produced.
        """
        pass

    def conclude(self, *, session_id: str) -> dict[str, Any]:
        """Finalise the investigation and return findings.

        Args:
            session_id: The investigation to conclude.

        Returns:
            Investigation summary with findings, confidence, and recommendations.
        """
        pass


class ResponsePlanner:
    """Plan and scope a response action given an investigation outcome.

    Consults policy and the Security Graph to decide which response
    actions are appropriate and produces a scoped response plan.
    """

    def plan(self, *, investigation_result: dict[str, Any]) -> dict[str, Any]:
        """Generate a response plan from investigation findings.

        Args:
            investigation_result: Findings dict from an InvestigationSession.

        Returns:
            A response plan dict describing recommended actions and scope.
        """
        pass
