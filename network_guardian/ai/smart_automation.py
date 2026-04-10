"""
Smart Task Automation — ML-driven task scheduling and prioritisation.

Uses historical task outcome data and current system state to:
- Recommend which maintenance tasks to run
- Prioritise tasks by predicted impact
- Auto-schedule recurring tasks based on learned timing patterns
- Estimate success probability for each task
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from network_guardian.automator import TaskResult, TaskStatus
    from network_guardian.models.network import Finding

logger = logging.getLogger("network_guardian.ai.smart_automation")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class TaskRecommendation:
    """A recommended task with estimated priority and success probability."""

    task_name: str
    reason: str
    priority: float  # 0.0 (low) to 1.0 (urgent)
    estimated_success: float  # probability 0.0 to 1.0
    related_findings: list[str] = field(default_factory=list)


@dataclass
class TaskProfile:
    """Learned profile for a task based on historical execution."""

    task_name: str
    total_runs: int = 0
    successes: int = 0
    failures: int = 0
    avg_duration_secs: float = 0.0
    last_run: datetime | None = None
    failure_streak: int = 0  # consecutive recent failures


# ---------------------------------------------------------------------------
# Smart automation engine
# ---------------------------------------------------------------------------

# Maps finding keywords → relevant task names
_FINDING_TO_TASK: dict[str, list[str]] = {
    "cleartext": ["enforce_encryption", "disable_legacy_protocols"],
    "brute-force": ["configure_fail2ban", "strengthen_passwords"],
    "no auth": ["enable_authentication", "configure_access_control"],
    "smb": ["patch_smb", "disable_smbv1"],
    "rdp": ["patch_rdp", "enable_nla"],
    "open ports": ["firewall_audit", "close_unused_ports"],
    "ssl": ["renew_certificates", "upgrade_tls"],
    "certificate": ["renew_certificates"],
    "dns amplification": ["configure_dns_ratelimit"],
    "anonymous": ["disable_anonymous_access"],
    "ransomware": ["backup_verification", "patch_smb"],
    "data exfiltration": ["enable_dlp", "configure_access_control"],
}

_SEVERITY_WEIGHT: dict[str, float] = {
    "info": 0.1, "low": 0.2, "medium": 0.4, "high": 0.7, "critical": 1.0,
}


class SmartAutomation:
    """ML-driven task recommendation and scheduling engine.

    Learns from historical task outcomes and current findings to produce
    prioritised task recommendations.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TaskProfile] = {}
        self._decay_factor: float = 0.95  # exponential weighting for recency

    # -- Learning from history ------------------------------------------

    def learn_from_history(self, history: list[TaskResult]) -> dict[str, TaskProfile]:
        """Process task execution history to build task profiles."""
        from network_guardian.automator import TaskStatus

        grouped: dict[str, list[TaskResult]] = defaultdict(list)
        for result in history:
            grouped[result.task_name].append(result)

        for name, results in grouped.items():
            results.sort(key=lambda r: r.started_at or datetime.min.replace(tzinfo=timezone.utc))
            profile = self._build_profile(name, results)
            self._profiles[name] = profile

        return dict(self._profiles)

    def _build_profile(self, name: str, results: list[TaskResult]) -> TaskProfile:
        from network_guardian.automator import TaskStatus

        profile = TaskProfile(task_name=name)
        profile.total_runs = len(results)
        profile.successes = sum(1 for r in results if r.status == TaskStatus.COMPLETED)
        profile.failures = sum(1 for r in results if r.status == TaskStatus.FAILED)
        profile.avg_duration_secs = self._avg_duration(results)
        profile.last_run = results[-1].finished_at
        profile.failure_streak = self._count_failure_streak(results)
        return profile

    @staticmethod
    def _avg_duration(results: list[TaskResult]) -> float:
        durations = [
            (r.finished_at - r.started_at).total_seconds()
            for r in results
            if r.started_at and r.finished_at
            and (r.finished_at - r.started_at).total_seconds() > 0
        ]
        return sum(durations) / len(durations) if durations else 0.0

    @staticmethod
    def _count_failure_streak(results: list[TaskResult]) -> int:
        from network_guardian.automator import TaskStatus
        streak = 0
        for r in reversed(results):
            if r.status == TaskStatus.FAILED:
                streak += 1
            else:
                break
        return streak

    # -- Recommendation engine ------------------------------------------

    def recommend_tasks(
        self,
        findings: list[Finding],
        available_tasks: list[str],
        max_recommendations: int = 10,
    ) -> list[TaskRecommendation]:
        """Generate prioritised task recommendations based on findings and history."""
        scores = self._match_findings_to_tasks(findings)
        recommendations = self._build_recommendations(scores)
        self._add_overdue_tasks(recommendations, scores, available_tasks)

        # Sort by priority descending
        recommendations.sort(key=lambda r: r.priority, reverse=True)
        return recommendations[:max_recommendations]

    def _match_findings_to_tasks(
        self, findings: list[Finding],
    ) -> dict[str, dict[str, Any]]:
        scores: dict[str, dict[str, Any]] = {}
        for finding in findings:
            text = f"{finding.title} {finding.description}".lower()
            for keyword, task_names in _FINDING_TO_TASK.items():
                if keyword not in text:
                    continue
                sev_weight = _SEVERITY_WEIGHT.get(finding.severity.value, 0.1)
                for task_name in task_names:
                    if task_name not in scores:
                        scores[task_name] = {"priority": 0.0, "reasons": [], "related": []}
                    scores[task_name]["priority"] = max(scores[task_name]["priority"], sev_weight)
                    scores[task_name]["reasons"].append(f"Addresses: {finding.title}")
                    scores[task_name]["related"].append(finding.title)
        return scores

    def _build_recommendations(
        self, scores: dict[str, dict[str, Any]],
    ) -> list[TaskRecommendation]:
        recommendations: list[TaskRecommendation] = []
        for task_name, data in scores.items():
            profile = self._profiles.get(task_name)
            success_prob = self._estimate_success(profile)

            if profile and profile.failure_streak >= 3:
                data["priority"] *= 0.5
                data["reasons"].append(
                    f"Warning: {profile.failure_streak} consecutive failures"
                )

            recommendations.append(TaskRecommendation(
                task_name=task_name,
                reason="; ".join(data["reasons"][:3]),
                priority=round(data["priority"], 3),
                estimated_success=round(success_prob, 3),
                related_findings=data["related"][:5],
            ))
        return recommendations

    def _add_overdue_tasks(
        self,
        recommendations: list[TaskRecommendation],
        scores: dict[str, dict[str, Any]],
        available_tasks: list[str],
    ) -> None:
        for task_name in available_tasks:
            if task_name in scores:
                continue
            profile = self._profiles.get(task_name)
            if not profile or not profile.last_run:
                continue
            hours_ago = (datetime.now(timezone.utc) - profile.last_run).total_seconds() / 3600
            if hours_ago > 168:  # hasn't run in a week
                recommendations.append(TaskRecommendation(
                    task_name=task_name,
                    reason=f"Overdue: last run {hours_ago:.0f}h ago",
                    priority=round(min(0.5, hours_ago / 720), 3),
                    estimated_success=round(self._estimate_success(profile), 3),
                ))

    def _estimate_success(self, profile: TaskProfile | None) -> float:
        """Estimate success probability from historical outcomes."""
        if profile is None or profile.total_runs == 0:
            return 0.7  # prior for unknown tasks

        # Weighted success rate with recency bias via beta distribution intuition
        # Add 1 smoothing (Laplace)
        alpha = profile.successes + 1
        beta = profile.failures + 1
        base_rate = alpha / (alpha + beta)

        # Penalise for recent failure streaks
        streak_penalty = self._decay_factor ** profile.failure_streak
        return base_rate * streak_penalty

    # -- Scheduling hints -----------------------------------------------

    def suggest_schedule(self, task_name: str) -> dict[str, Any]:
        """Suggest optimal scheduling based on learned patterns."""
        profile = self._profiles.get(task_name)
        if profile is None:
            return {"interval_hours": 24, "confidence": "low", "reason": "no history"}

        # Simple heuristic: frequent failures → longer intervals
        if profile.failure_streak > 0:
            interval = min(168, 24 * (2 ** profile.failure_streak))
            return {
                "interval_hours": interval,
                "confidence": "medium",
                "reason": f"Backing off due to {profile.failure_streak} failures",
            }

        # Success: maintain current cadence or speed up
        success_rate = profile.successes / max(profile.total_runs, 1)
        if success_rate > 0.9:
            interval = max(4, 24 * (1 - success_rate * 0.5))
        else:
            interval = 24
        return {
            "interval_hours": round(interval, 1),
            "confidence": "high" if profile.total_runs > 10 else "medium",
            "reason": f"Success rate: {success_rate:.0%}",
        }
