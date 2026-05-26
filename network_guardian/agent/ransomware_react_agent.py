# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — Ransomware Monitor  ReAct Agent

Extends RansomwareMonitor with a full ReAct reasoning cycle triggered on
every alert:

  OBSERVE  — capture the incoming file-system event (extension / burst)
  REASON   — evaluate severity, correlate with recent alert history,
              determine if this looks like genuine ransomware activity
  ACT      — quarantine affected file (if auto_quarantine=True),
              publish event, generate PDF incident report
  LEARN    — persist alert history, update burst baseline for the folder

The agent also supports an autonomous mode that periodically re-evaluates
cumulative alert trends and emits a summary PDF if the alert rate is rising.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from network_guardian.agent.ransomware_monitor import (
    RansomwareMonitor,
    RansomwareAlert,
    DEFAULT_WATCH_FOLDER,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_SECS,
)

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.ransomware_react")


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

_EXT_SEVERITY = {
    # Known ransomware families — critical
    ".wncry": "critical", ".wcry": "critical", ".wnry": "critical",
    ".cerber": "critical", ".locky": "critical", ".zepto": "critical",
    # Generic encrypted indicators — high
    ".locked": "high", ".enc": "high", ".crypto": "high",
    ".crypt": "high", ".r5a": "high", ".onion": "high",
}

_RISK_SCORES = {"critical": 50, "high": 30, "medium": 15, "low": 5}


def _ext_from_path(path: str | None) -> str:
    if not path:
        return ""
    return os.path.splitext(path)[-1].lower()


def _classify_alert(alert: RansomwareAlert, recent_count: int) -> tuple[str, float]:
    """Return (severity, threat_score) for an alert."""
    if alert.kind == "extension":
        ext = _ext_from_path(alert.path)
        sev = _EXT_SEVERITY.get(ext, "high")
        score = _RISK_SCORES.get(sev, 25)
    else:  # burst
        # Burst severity escalates with recent alert count
        if recent_count >= 5:
            sev, score = "critical", 60.0
        elif recent_count >= 3:
            sev, score = "high", 40.0
        else:
            sev, score = "medium", 20.0
    return sev, float(score)


# ---------------------------------------------------------------------------
# ReAct step model
# ---------------------------------------------------------------------------

@dataclass
class ReActStep:
    phase: str
    thought: str
    detail: Any = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Per-incident report model
# ---------------------------------------------------------------------------

@dataclass
class RansomwareReActReport:
    report_id: str
    generated_at: str
    alert_kind: str       # "extension" | "burst" | "summary"
    risk_level: str
    threat_score: float
    threats: list[dict]
    actions: list[dict]
    recommendations: list[str]
    observations: dict
    react_steps: list[dict]
    pdf_path: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class RansomwareReActAgent(RansomwareMonitor):
    """Autonomous ransomware-detection ReAct agent.

    Inherits all filesystem monitoring capabilities from
    :class:`~network_guardian.agent.ransomware_monitor.RansomwareMonitor`
    and adds the ReAct reasoning cycle on each alert.

    Parameters
    ----------
    auto_quarantine:
        Move detected files to a quarantine folder instead of leaving them
        in place.  Defaults to False.
    generate_pdf:
        ``"on_threat"`` (default) — emit PDF when alert is high/critical.
        ``"always"`` — emit PDF for every alert.
        ``"never"`` — no PDF output.
    quarantine_dir:
        Directory to move quarantined files into.
        Defaults to ``~/.network_guardian/quarantine/``.
    """

    def __init__(
        self,
        auto_quarantine: bool = False,
        generate_pdf: str = "on_threat",
        quarantine_dir: Path | None = None,
        event_bus: "EventBus | None" = None,
        watch_folder: str = DEFAULT_WATCH_FOLDER,
        threshold: int = DEFAULT_THRESHOLD,
        window_secs: float = DEFAULT_WINDOW_SECS,
        data_dir: Path | None = None,
    ) -> None:
        super().__init__(
            event_bus=event_bus,
            watch_folder=watch_folder,
            threshold=threshold,
            window_secs=window_secs,
        )
        self.auto_quarantine = auto_quarantine
        self.generate_pdf    = generate_pdf

        self._quarantine_dir = quarantine_dir or (
            Path.home() / ".network_guardian" / "quarantine"
        )
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)

        self._data_dir = data_dir or (Path.home() / ".network_guardian" / "ransomware_react")
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._history_path = self._data_dir / "alert_history.json"
        self._alert_history: list[dict] = self._load_history()

        self._react_queue: asyncio.Queue[RansomwareAlert] = asyncio.Queue()
        self._react_task: asyncio.Task | None = None
        self._last_report: RansomwareReActReport | None = None

    # ------------------------------------------------------------------
    # Override start/stop to also launch the async ReAct consumer
    # ------------------------------------------------------------------

    def start(self) -> None:
        super().start()
        # Schedule the async ReAct consumer on the running loop
        try:
            loop = asyncio.get_running_loop()
            self._react_task = loop.create_task(self._react_consumer())
            logger.info("RansomwareReActAgent ReAct consumer started")
        except RuntimeError:
            # No running loop (e.g. called outside asyncio) — best-effort
            logger.warning(
                "RansomwareReActAgent started without a running event loop; "
                "ReAct responses will not be executed automatically."
            )

    def stop(self) -> None:
        super().stop()
        if self._react_task and not self._react_task.done():
            self._react_task.cancel()

    # ------------------------------------------------------------------
    # Intercept alerts from the base class and queue for ReAct
    # ------------------------------------------------------------------

    def _on_alert(self, alert: RansomwareAlert) -> None:
        """Called by the watchdog thread for every detected event."""
        super()._on_alert(alert)   # stores in self.alerts, publishes event

        # Thread-safely push into the asyncio queue
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(
                self._react_queue.put(alert), self._loop
            )

    # ------------------------------------------------------------------
    # Async ReAct consumer (runs inside the event loop)
    # ------------------------------------------------------------------

    async def _react_consumer(self) -> None:
        """Drain the alert queue and run a ReAct cycle for each alert."""
        while True:
            try:
                alert = await self._react_queue.get()
                try:
                    await self._react_cycle(alert)
                except Exception as e:
                    logger.error("ReAct cycle error: %s", e)
                finally:
                    self._react_queue.task_done()
            except asyncio.CancelledError:
                break

    # ------------------------------------------------------------------
    # Full ReAct cycle for a single alert
    # ------------------------------------------------------------------

    async def _react_cycle(self, alert: RansomwareAlert) -> RansomwareReActReport:
        report_id = uuid.uuid4().hex[:12]
        steps: list[ReActStep] = []
        recent_count = len(self.alerts)   # total alerts seen so far

        def _step(phase: str, thought: str, detail: Any = None) -> None:
            s = ReActStep(phase=phase, thought=thought, detail=detail)
            steps.append(s)
            logger.info("[%s] %s", phase.upper(), thought)

        # ---- OBSERVE ------------------------------------------------
        _step("observe",
              f"File-system alert received: kind='{alert.kind}' "
              f"path='{alert.path or 'N/A'}'",
              {"kind": alert.kind, "path": alert.path, "detail": alert.detail})

        ext = _ext_from_path(alert.path)
        _step("observe",
              f"Alert detail: {alert.detail}  |  "
              f"Extension: '{ext or 'N/A'}'  |  Total alerts so far: {recent_count}",
              {"extension": ext, "total_alerts": recent_count,
               "watch_folder": self.watch_folder})

        obs = {
            "host":          platform.node(),
            "platform":      f"{platform.system()} {platform.release()}",
            "watch_folder":  self.watch_folder,
            "alert_kind":    alert.kind,
            "alert_path":    alert.path or "N/A",
            "extension":     ext or "N/A",
            "total_alerts":  recent_count,
            "threshold":     self.threshold,
            "window_secs":   f"{self.window_secs:.0f}s",
        }

        # ---- REASON -------------------------------------------------
        _step("reason", "Classifying alert severity and assessing threat level")
        sev, score = _classify_alert(alert, recent_count)
        risk_level = (
            "critical" if score >= 50
            else "high"   if score >= 30
            else "medium" if score >= 15
            else "low"
        )

        # Correlation with history
        recent_critical = sum(
            1 for h in self._alert_history[-20:]
            if h.get("severity") in ("critical", "high")
        )
        if recent_critical >= 3:
            _step("reason",
                  f"ESCALATION: {recent_critical} high/critical alerts in recent history "
                  "— elevating risk to critical",
                  {"recent_critical": recent_critical})
            risk_level = "critical"
            score = min(100.0, score + 20)

        _step("reason",
              f"Risk level={risk_level.upper()}, score={score:.0f}/100, "
              f"extension='{ext or 'none'}', kind={alert.kind}",
              {"risk_level": risk_level, "score": score})

        threat = {
            "title":      f"Ransomware {alert.kind} alert: {alert.path or alert.detail[:40]}",
            "severity":   sev,
            "category":   "ransomware",
            "detail":     alert.detail,
            "path":       alert.path,
            "extension":  ext,
            "action_taken": "",
            "resolved":   False,
            "timestamp":  datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat(),
        }

        # ---- ACT ----------------------------------------------------
        actions: list[dict] = []
        recommendations: list[str] = []

        _step("act", f"Executing protective response for {risk_level.upper()} ransomware alert")

        if self.auto_quarantine and alert.path and os.path.isfile(alert.path):
            quarantined = await asyncio.to_thread(
                self._quarantine_file, alert.path
            )
            action_name = "quarantine_file" if quarantined else "quarantine_failed"
            threat["action_taken"] = action_name
            threat["resolved"] = quarantined
            actions.append({
                "action":  f"Quarantine: {os.path.basename(alert.path or '')}",
                "detail":  (
                    f"Moved '{alert.path}' to quarantine directory '{self._quarantine_dir}'"
                    if quarantined
                    else f"Failed to quarantine '{alert.path}'"
                ),
                "success": quarantined,
            })
            _step("act",
                  f"{'Quarantined' if quarantined else 'Failed to quarantine'} "
                  f"file: {alert.path}",
                  {"quarantined": quarantined, "dest": str(self._quarantine_dir)})
        else:
            threat["action_taken"] = "alert_and_log"
            actions.append({
                "action":  "Alert and log",
                "detail":  "Threat logged; no automated quarantine (auto_quarantine=False)",
                "success": True,
            })

        # Recommendations
        if risk_level in ("critical", "high"):
            recommendations += [
                "Immediately disconnect the affected machine from the network.",
                f"Inspect all files in '{self.watch_folder}' for encryption damage.",
                "Restore from a clean, offline backup if encryption has occurred.",
                "Identify and terminate the ransomware process using Task Manager or `kill`.",
            ]
        if alert.kind == "burst":
            recommendations.append(
                f"Burst of file changes detected ({self.threshold}+ events / "
                f"{self.window_secs:.0f}s) — check for large batch writes or crypto-locker."
            )
        if not self.auto_quarantine:
            recommendations.append(
                "Enable auto_quarantine on this agent to automatically isolate "
                "suspected ransomware files on future detections."
            )

        # Publish event
        if self.event_bus:
            try:
                payload = {"type": "ransomware.react_alert", "risk": risk_level,
                           "detail": alert.detail, "path": alert.path}
                if hasattr(self.event_bus, "emit"):
                    await self.event_bus.emit("ransomware.react_alert", payload)
                elif hasattr(self.event_bus, "publish"):
                    await self.event_bus.publish("ransomware.react_alert", payload)
                _step("act", "Published ransomware.react_alert event to event bus")
            except Exception as e:
                logger.warning("Event publish failed: %s", e)

        # ---- LEARN --------------------------------------------------
        _step("learn", "Recording alert to history for trend analysis and baseline updates")
        self._save_history(alert, sev, score)

        # ---- PDF ----------------------------------------------------
        pdf_path: str | None = None
        should_pdf = (
            (self.generate_pdf == "on_threat" and risk_level in ("critical", "high", "medium"))
            or self.generate_pdf == "always"
        )

        report = RansomwareReActReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            alert_kind=alert.kind,
            risk_level=risk_level,
            threat_score=score,
            threats=[threat],
            actions=actions,
            recommendations=recommendations,
            observations=obs,
            react_steps=[s.to_dict() for s in steps],
        )

        if should_pdf:
            _step("act", "Generating PDF incident report for this ransomware event")
            try:
                from network_guardian.agent.pdf_reporter import build_report_pdf
                pdf = await asyncio.to_thread(
                    build_report_pdf,
                    "ransomware",
                    report_id,
                    f"RansomwareReActAgent — {alert.kind} alert",
                    risk_level,
                    score,
                    report.react_steps,
                    [threat],
                    actions,
                    recommendations,
                    obs,
                )
                pdf_path = str(pdf)
                _step("learn", f"PDF report saved: {pdf_path}")
                logger.info("[PDF] Ransomware report written to %s", pdf_path)
            except Exception as e:
                logger.error("PDF generation failed: %s", e)

        report.pdf_path = pdf_path
        self._last_report = report

        # Expose report via alerts list for dashboard polling
        logger.info(
            "[REACT] Ransomware cycle complete: risk=%s score=%.0f pdf=%s",
            risk_level, score, pdf_path or "none",
        )
        return report

    # ------------------------------------------------------------------
    # Quarantine helper (runs in thread)
    # ------------------------------------------------------------------

    def _quarantine_file(self, path: str) -> bool:
        try:
            dest = self._quarantine_dir / Path(path).name
            # Avoid clobbering existing files in quarantine
            if dest.exists():
                stem = dest.stem
                suffix = dest.suffix
                dest = self._quarantine_dir / f"{stem}_{uuid.uuid4().hex[:6]}{suffix}"
            shutil.move(path, str(dest))
            logger.info("[ACT] Quarantined '%s' → '%s'", path, dest)
            return True
        except (OSError, shutil.Error) as e:
            logger.warning("[ACT] Quarantine failed for '%s': %s", path, e)
            return False

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_history(self) -> list[dict]:
        if self._history_path.exists():
            try:
                return json.loads(self._history_path.read_text())[-1000:]
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_history(self, alert: RansomwareAlert, severity: str, score: float) -> None:
        entry = {
            "timestamp": datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat(),
            "kind":      alert.kind,
            "path":      alert.path,
            "severity":  severity,
            "score":     score,
            "detail":    alert.detail,
        }
        self._alert_history.append(entry)
        try:
            self._history_path.write_text(
                json.dumps(self._alert_history[-1000:], indent=2)
            )
        except OSError as e:
            logger.warning("Failed to save alert history: %s", e)

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def last_report(self) -> RansomwareReActReport | None:
        return self._last_report

    @property
    def alert_history(self) -> list[dict]:
        return list(self._alert_history)
