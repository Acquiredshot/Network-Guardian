# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
AI Security Orchestrator — Investigation layer.

Consumes DetectionFindings from the Detection layer, enriches them with
context from the Security Graph, and produces investigation cases.

Investigation pipeline:
    DetectionFinding ──► Context enrichment (Security Graph) ──► InvestigationCase
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CaseStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass
class InvestigationCase:
    """A single investigation case produced by the orchestrator."""

    case_id: str
    title: str
    status: CaseStatus = CaseStatus.OPEN
    findings: list[str] = field(default_factory=list)  # finding IDs
    context: dict[str, Any] = field(default_factory=dict)  # graph-enriched context
    assignee: str = ""
    priority: str = "medium"  # low, medium, high, critical
    notes: list[str] = field(default_factory=list)
    created_at: float = 0.0
    resolved_at: float = 0.0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status.value,
            "finding_count": len(self.findings),
            "priority": self.priority,
            "has_notes": len(self.notes) > 0,
        }


class InvestigationEngine:
    """Phase 1 investigation engine — creates cases from findings + graph context."""

    def __init__(self, security_graph: Any | None = None) -> None:
        self._graph = security_graph
        self._cases: list[InvestigationCase] = []
        self._counter = 0

    def investigate(self, findings: list[dict[str, Any]]) -> list[InvestigationCase]:
        """Create investigation cases from a list of findings.

        Phase 1: one case per unique finding cluster (grouped by event source).
        Phase 2+: graph traversal for related entities, automated triage.
        """
        cases: list[InvestigationCase] = []
        grouped: dict[str, list[dict[str, Any]]] = {}

        for finding in findings:
            source = finding.get("event_source", finding.get("context", {}).get("source", "unknown"))
            grouped.setdefault(source, []).append(finding)

        now = 0.0
        for source, group in grouped.items():
            case = self._build_case(source, group, now)
            cases.append(case)
            self._cases.append(case)

        return cases

    def get_cases(self, status: CaseStatus | None = None) -> list[InvestigationCase]:
        if status is None:
            return list(self._cases)
        return [c for c in self._cases if c.status == status]

    def enrich_case(self, case: InvestigationCase, context: dict[str, Any]) -> InvestigationCase:
        """Enrich a case with context from the Security Graph."""
        case.context.update(context)
        return case

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_case(self, source: str, findings: list[dict[str, Any]], now: float) -> InvestigationCase:
        finding_ids = [f.get("finding_id", "") for f in findings]
        max_sev = "info"
        for f in findings:
            sev = f.get("severity", "info")
            if sev in ("critical", "high"):
                max_sev = sev
            elif sev == "medium" and max_sev not in ("critical", "high"):
                max_sev = sev

        priority_map = {"critical": "critical", "high": "high", "medium": "medium"}
        priority = priority_map.get(max_sev, "medium")

        return InvestigationCase(
            case_id=f"case-{int(now * 1000)}-{self._counter}",
            title=f"Investigation: {source} — {len(findings)} finding(s)",
            status=CaseStatus.OPEN,
            findings=finding_ids,
            context={"source": source, "max_severity": max_sev},
            priority=priority,
            created_at=now,
        )
