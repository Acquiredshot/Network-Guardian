"""
NLP module — natural language processing for text analysis.

Handles parsing of log messages, command interpretation, and
generating human-readable summaries from structured data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.ai.nlp")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Intent:
    """A parsed user intent from natural language input."""

    action: str  # e.g. "audit", "explore", "monitor"
    targets: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    raw_text: str = ""


@dataclass
class LogPattern:
    """A known pattern in log text."""

    name: str
    regex: str
    severity: str = "info"
    description: str = ""


# ---------------------------------------------------------------------------
# NLP Engine
# ---------------------------------------------------------------------------

# Simple keyword → action mappings for command interpretation
_ACTION_KEYWORDS: dict[str, list[str]] = {
    "audit": ["audit", "scan", "check", "vulnerability", "security"],
    "explore": ["explore", "discover", "map", "topology", "find hosts"],
    "monitor": ["monitor", "watch", "observe", "track", "alert"],
    "status": ["status", "health", "state", "info"],
    "tasks": ["task", "automate", "run job", "schedule"],
    "help": ["help", "commands", "usage", "?"],
}

# Common log patterns
_DEFAULT_LOG_PATTERNS: list[LogPattern] = [
    LogPattern(
        name="auth_failure",
        regex=r"(?i)(authentication|login)\s+(fail|error|denied)",
        severity="high",
        description="Authentication failure detected",
    ),
    LogPattern(
        name="connection_refused",
        regex=r"(?i)connection\s+refused",
        severity="medium",
        description="Connection refused by remote host",
    ),
    LogPattern(
        name="timeout",
        regex=r"(?i)(timed?\s*out|timeout)",
        severity="medium",
        description="Operation timed out",
    ),
    LogPattern(
        name="disk_space",
        regex=r"(?i)(disk|storage)\s+(full|low|space)",
        severity="high",
        description="Disk space issue detected",
    ),
    LogPattern(
        name="permission_denied",
        regex=r"(?i)permission\s+denied",
        severity="medium",
        description="Permission denied",
    ),
]


class NLPEngine:
    """Lightweight NLP engine for command parsing and log analysis.

    For production use, integrate spaCy or a transformer model via the
    plugin system.  This built-in engine uses keyword matching and regex.
    """

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus
        self._log_patterns: list[LogPattern] = list(_DEFAULT_LOG_PATTERNS)

    # -- Command interpretation -----------------------------------------

    def parse_intent(self, text: str) -> Intent:
        """Parse natural language input into a structured Intent."""
        lower = text.lower().strip()
        best_action = "unknown"
        best_score = 0.0

        for action, keywords in _ACTION_KEYWORDS.items():
            for kw in keywords:
                if kw in lower:
                    score = len(kw) / len(lower) if lower else 0
                    if score > best_score:
                        best_score = score
                        best_action = action

        # Extract IP-like targets
        targets = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", text
        )

        return Intent(
            action=best_action,
            targets=targets,
            confidence=min(best_score * 2, 1.0),
            raw_text=text,
        )

    # -- Log analysis ---------------------------------------------------

    def analyse_logs(self, lines: list[str]) -> list[dict[str, Any]]:
        """Scan log lines for known patterns.

        Returns a list of matches with pattern name, severity, and line.
        """
        matches: list[dict[str, Any]] = []
        for i, line in enumerate(lines):
            for pat in self._log_patterns:
                if re.search(pat.regex, line):
                    matches.append({
                        "line_number": i + 1,
                        "line": line.strip(),
                        "pattern": pat.name,
                        "severity": pat.severity,
                        "description": pat.description,
                    })
        return matches

    def register_log_pattern(self, pattern: LogPattern) -> None:
        self._log_patterns.append(pattern)

    # -- Summarisation --------------------------------------------------

    def summarise_findings(self, findings: list[dict[str, Any]]) -> str:
        """Generate a human-readable summary from structured findings."""
        if not findings:
            return "No issues detected."

        summary_parts = [f"Detected {len(findings)} issue(s):\n"]
        for f in findings:
            sev = f.get("severity", "info").upper()
            title = f.get("title") or f.get("pattern", "Unknown")
            desc = f.get("description", "")
            summary_parts.append(f"  [{sev}] {title}: {desc}")

        return "\n".join(summary_parts)
