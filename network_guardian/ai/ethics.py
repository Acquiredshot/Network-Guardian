# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
AI Ethics — responsible AI pillars for Network Guardian.

Implements five pillars of ethical AI:
  1. Output Filtering      — sanitize AI-generated text before it reaches users
  2. Harmful Content       — block content that enables attacks or harm
  3. Illegal Instructions  — refuse content suggesting unauthorized/illegal actions
  4. Misinformation Guard  — enforce confidence thresholds; flag uncertain outputs
  5. Transparency          — label all AI content; expose confidence + reasoning
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian.ai.ethics")

# ---------------------------------------------------------------------------
# Confidence thresholds
# ---------------------------------------------------------------------------

# Minimum threat score to report as a confirmed threat
_CONFIRMED_THREAT_MIN_SCORE: float = 30.0
# Minimum score to surface at all (below = noise, do not report)
_ANOMALY_MIN_SCORE: float = 15.0

# ---------------------------------------------------------------------------
# Pillar 2 & 3: Harmful content + illegal instruction patterns
#
# This is a DEFENSIVE security tool. Block AI outputs that suggest:
#   - Offensive attacks against external/unauthorized systems
#   - Malware or exploit creation
#   - Illegal access instructions
#   - Social engineering scripts
# ---------------------------------------------------------------------------

_HARMFUL_PATTERNS: list[tuple[str, str]] = [
    (
        r"(?i)\b(attack|exploit|hack|pwn|compromise|breach)\s+(the\s+)?(target|external|remote|victim)\b",
        "offensive_attack_guidance",
    ),
    (
        r"(?i)\b(create|write|build|generate|deploy)\s+(a\s+)?(malware|ransomware|virus|trojan|rootkit|keylogger|backdoor|worm)\b",
        "malware_creation",
    ),
    (
        r"(?i)\bgain\s+(unauthorized|illegal)\s+access\b",
        "illegal_access_instruction",
    ),
    (
        r"(?i)\b(steal|harvest|dump)\s+(credentials|passwords|hashes|tokens)\s+(from|of)\s+\w+\b",
        "credential_theft_instruction",
    ),
    (
        r"(?i)\b(phishing\s+email|spear.?phishing)\s+(template|script|payload)\b",
        "social_engineering_content",
    ),
]

_HATE_SPEECH_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\b(kill|murder|harm)\s+(all\s+)?(people|users|humans)\b", "violent_content"),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result of running the ethics filter on a piece of AI-generated text."""

    allowed: bool
    sanitized_text: str
    flags: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def was_modified(self) -> bool:
        return bool(self.flags)


@dataclass
class ConfidenceCheck:
    """Result of a confidence threshold check on an AI score."""

    verified: bool
    score: float
    threshold: float
    label: str          # "confirmed" | "unverified" | "noise"
    warning: str = ""


# ---------------------------------------------------------------------------
# Core ethics filter
# ---------------------------------------------------------------------------


class EthicsFilter:
    """
    Central AI ethics enforcement for Network Guardian.

    Five pillars:
      1. filter_output()       — output filtering + harmful content + illegal instructions
      2. check_confidence()    — misinformation guard (confidence thresholds)
      3. transparency_meta()   — transparency metadata for every AI output
      4. wrap_report()         — apply all pillars to a full AI report dict
      5. _audit()              — append immutable audit log entry
    """

    def __init__(self, audit_log_dir: Path | None = None) -> None:
        self._audit_dir = audit_log_dir or Path.home() / ".ng_agent" / "ethics_audit"
        self._audit_dir.mkdir(parents=True, exist_ok=True)
        self._audit_file = self._audit_dir / "ethics_audit.jsonl"

    # ------------------------------------------------------------------
    # Pillars 1, 2, 3 — Output filtering / harmful content / illegal instructions
    # ------------------------------------------------------------------

    def filter_output(self, text: str, context: str = "") -> FilterResult:
        """
        Scan AI-generated text for harmful or illegal content.

        Matches are redacted in place (the response is returned sanitized rather
        than silently dropped, so operators can see that a filter fired).
        All filter events are written to the ethics audit log.
        """
        if not text or not text.strip():
            return FilterResult(allowed=True, sanitized_text=text)

        flags: list[str] = []
        sanitized = text

        for pattern, flag_name in _HARMFUL_PATTERNS + _HATE_SPEECH_PATTERNS:
            if re.search(pattern, text):
                flags.append(flag_name)
                sanitized = re.sub(pattern, "[REDACTED — ETHICS POLICY]", sanitized)
                logger.warning(
                    "[ETHICS] Content filtered: flag=%s context=%s", flag_name, context
                )
                self._audit(
                    {"event": "content_filtered", "flag": flag_name, "context": context}
                )

        if flags:
            return FilterResult(
                allowed=True,
                sanitized_text=sanitized,
                flags=flags,
                reason=f"Content modified by ethics filter: {', '.join(flags)}",
            )

        return FilterResult(allowed=True, sanitized_text=text)

    # ------------------------------------------------------------------
    # Pillar 4 — Misinformation guard
    # ------------------------------------------------------------------

    def check_confidence(self, score: float) -> ConfidenceCheck:
        """
        Validate an AI threat score against minimum confidence thresholds.

        Scores below the noise floor must not be surfaced as threats — doing so
        would constitute AI misinformation (false positives presented as fact).
        """
        if score < _ANOMALY_MIN_SCORE:
            return ConfidenceCheck(
                verified=False,
                score=score,
                threshold=_ANOMALY_MIN_SCORE,
                label="noise",
                warning=(
                    "Score below minimum threshold — signal suppressed to prevent "
                    "false-positive misinformation."
                ),
            )
        if score < _CONFIRMED_THREAT_MIN_SCORE:
            return ConfidenceCheck(
                verified=True,
                score=score,
                threshold=_CONFIRMED_THREAT_MIN_SCORE,
                label="unverified",
                warning=(
                    "Low-confidence signal. Treat as informational only. "
                    "Requires human review before acting."
                ),
            )
        return ConfidenceCheck(
            verified=True,
            score=score,
            threshold=_CONFIRMED_THREAT_MIN_SCORE,
            label="confirmed",
        )

    # ------------------------------------------------------------------
    # Pillar 5 — Transparency
    # ------------------------------------------------------------------

    def transparency_meta(
        self,
        score: float = 0.0,
        reasoning: str = "",
        engine: str = "network_guardian_react_agent",
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Build the transparency metadata block attached to every AI output.

        Informs operators:
          - That the content is AI-generated (not a human analyst)
          - Which engine produced it
          - The confidence level and label
          - Any ethics flags raised
          - A summary of the reasoning that led to the output
        """
        confidence = self.check_confidence(score)
        return {
            "ai_generated": True,
            "engine": engine,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "confidence_score": round(score, 1),
            "confidence_label": confidence.label,
            "confidence_warning": confidence.warning or None,
            "ethics_checked": True,
            "ethics_flags": flags or [],
            "reasoning_summary": (reasoning[:500] if reasoning else ""),
        }

    def wrap_report(
        self,
        report_dict: dict[str, Any],
        score: float = 0.0,
        reasoning: str = "",
    ) -> dict[str, Any]:
        """
        Apply all ethics pillars to a full AI-generated report dict.

        - Filters the narrative and each recommendation through the content filter
        - Attaches transparency metadata under the '_ai_transparency' key
        - Writes an audit log entry

        Call this on every AI report before returning it to the dashboard or user.
        """
        all_flags: list[str] = []

        # Filter narrative
        narrative = report_dict.get("narrative", "")
        if narrative:
            result = self.filter_output(narrative, context="narrative")
            report_dict["narrative"] = result.sanitized_text
            all_flags.extend(result.flags)

        # Filter each recommendation
        recs = report_dict.get("recommendations", [])
        filtered_recs: list[str] = []
        for rec in recs:
            r = self.filter_output(str(rec), context="recommendation")
            filtered_recs.append(r.sanitized_text)
            all_flags.extend(r.flags)
        report_dict["recommendations"] = filtered_recs

        # Attach transparency metadata
        report_dict["_ai_transparency"] = self.transparency_meta(
            score=score,
            reasoning=reasoning,
            flags=all_flags,
        )

        self._audit(
            {
                "event": "report_wrapped",
                "report_id": report_dict.get("report_id", ""),
                "score": score,
                "flags": all_flags,
            }
        )
        return report_dict

    # ------------------------------------------------------------------
    # Audit log (append-only JSONL)
    # ------------------------------------------------------------------

    def _audit(self, data: dict[str, Any]) -> None:
        """
        Append an immutable entry to the ethics audit log.

        The audit log is kept at ~/.ng_agent/ethics_audit/ethics_audit.jsonl.
        It records every filter event, confidence check, and report wrap so
        there is a permanent record of AI decisions for accountability.
        """
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), **data}
        try:
            with self._audit_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception as exc:
            logger.debug("[ETHICS] Audit log write failed: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------

_default_filter = EthicsFilter()


def filter_output(text: str, context: str = "") -> FilterResult:
    """Run the ethics content filter on a piece of AI-generated text."""
    return _default_filter.filter_output(text, context)


def check_confidence(score: float) -> ConfidenceCheck:
    """Check a threat score against the misinformation guard thresholds."""
    return _default_filter.check_confidence(score)


def wrap_report(
    report_dict: dict[str, Any],
    score: float = 0.0,
    reasoning: str = "",
) -> dict[str, Any]:
    """Apply all ethics pillars to an AI report dict before serving it."""
    return _default_filter.wrap_report(report_dict, score, reasoning)


def transparency_meta(
    score: float = 0.0,
    reasoning: str = "",
    engine: str = "network_guardian_react_agent",
) -> dict[str, Any]:
    """Return a transparency metadata dict for an AI output."""
    return _default_filter.transparency_meta(score=score, reasoning=reasoning, engine=engine)
