"""Pakshield core surface — public API entry points.


This module exposes the primary interfaces consumers use to interact
with Pakshield's identity risk and access control capabilities.
"""


class IdentityRiskEvaluator:
    """Assess identity risk for a given principal.

    Consumes identity signals, behavioural indicators, and
    contextual telemetry to produce a risk score and verdict.
    """

    def evaluate(self, *, principal_id: str, context: dict) -> dict:
        """Evaluate identity risk for a principal.

        Args:
            principal_id: Stable identifier for the principal being assessed.
            context: Arbitrary context dict (session, location, device, etc.).

        Returns:
            A dict with at minimum ``risk_score`` (float 0-100) and
            ``verdict`` (one of ``low``, ``elevated``, ``high``).
        """
        pass


class AccessReviewSession:
    """Represent an in-progress access review for a principal.

    Holds state for a single review lifecycle: queued -> evaluating
    -> approved / denied / escalated.
    """

    def start(self, *, principal_id: str, requested_by: str) -> str:
        """Begin an access review and return a session id.

        Args:
            principal_id: Principal whose access is under review.
            requested_by: Identifier of the actor requesting the review.

        Returns:
            A session identifier string.
        """
        pass

    def add_evidence(self, *, session_id: str, evidence: dict) -> None:
        """Attach evidence to an ongoing review.

        Args:
            session_id: The review session to enrich.
            evidence: Dict of evidence key-value pairs.
        """
        pass

    def conclude(self, *, session_id: str, decision: str) -> dict:
        """Finalise the review with a decision.

        Args:
            session_id: The review session to conclude.
            decision: One of ``approved``, ``denied``, ``escalated``.

        Returns:
            A summary dict of the concluded session.
        """
        pass
