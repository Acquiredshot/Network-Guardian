"""
Network Guardian — Email Protection  ReAct Agent

Wraps the EmailScanner inside a full Observe → Reason → Act → Learn cycle
that runs autonomously on a configurable interval:

  OBSERVE  — connect to IMAP, fetch unseen messages, record counts
  REASON   — classify each flagged message by severity (spam / malware /
              both); compute a cumulative threat score for the scan cycle
  ACT      — log threats, optionally quarantine attachments, publish events,
              generate PDF report on high/critical cycles
  LEARN    — persist scan history for trend analysis; update baseline

Designed to mirror the MalwareReActAgent and RansomwareReActAgent patterns
so it slots seamlessly into the dashboard Threat Detection page.

Typical usage::

    import asyncio
    from network_guardian.agent.email_react_agent import (
        EmailReActAgent, EmailReActConfig,
    )

    agent = EmailReActAgent(
        EmailReActConfig(
            imap_host="imap.gmail.com",
            imap_user="you@gmail.com",
            imap_password="app-password",
        )
    )
    # One-shot cycle
    report = asyncio.run(agent.run_cycle())
    print(report.risk_level, report.threat_score)

    # Autonomous loop (scans every 5 minutes)
    asyncio.run(agent.run())
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from network_guardian.agent.email_scanner import (
    EmailScanConfig,
    EmailScanResult,
    EmailScanner,
)

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.email_react")


# ---------------------------------------------------------------------------
# Severity / scoring
# ---------------------------------------------------------------------------

# Spam-score bands → severity
def _spam_severity(score: float) -> str:
    if score >= 15.0:
        return "critical"
    if score >= 10.0:
        return "high"
    if score >= 5.0:
        return "medium"
    return "low"


_RISK_SCORES: dict[str, float] = {
    "critical": 40.0,
    "high": 25.0,
    "medium": 10.0,
    "low": 3.0,
}


def _classify_result(result: EmailScanResult) -> tuple[str, str]:
    """Return (severity, category) for a flagged EmailScanResult."""
    if result.malware.is_infected:
        return "critical", "email_malware"
    if result.spam.is_spam:
        sev = _spam_severity(result.spam.score)
        return sev, "email_spam"
    return "low", "email_suspicious"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class EmailReActConfig:
    """IMAP + agent behaviour settings."""
    imap_host: str
    imap_user: str
    imap_password: str
    imap_port: int = 993
    imap_use_ssl: bool = True
    mailbox: str = "INBOX"
    spam_threshold: float = 5.0
    fetch_limit: int = 50
    # Active protection mode passed through to EmailScanner:
    #   "monitor"    — detect and report only (default, safe)
    #   "move_spam"  — move spam to Junk/Spam folder; delete malware
    #   "delete_all" — permanently delete all flagged messages
    action_mode: str = "monitor"
    # Override the spam destination folder (auto-detected by provider if empty)
    spam_folder: str = ""
    # Agent behaviour
    interval_secs: float = 300.0          # polling interval
    generate_pdf: str = "on_threat"       # "on_threat" | "always" | "never"


# ---------------------------------------------------------------------------
# Data models
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


@dataclass
class EmailReActReport:
    report_id: str
    generated_at: str
    cycle: int
    risk_level: str
    threat_score: float
    messages_scanned: int
    messages_flagged: int
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

class EmailReActAgent:
    """Autonomous email-protection ReAct agent.

    Parameters
    ----------
    config:
        IMAP connection and agent behaviour settings.
    event_bus:
        Optional Network Guardian event bus for publishing alerts.
    data_dir:
        Directory for persisting scan history and PDF reports.
        Defaults to ``~/.network_guardian/email_react/``.
    """

    def __init__(
        self,
        config: EmailReActConfig,
        event_bus: "EventBus | None" = None,
        data_dir: Path | None = None,
    ) -> None:
        self._cfg = config
        self.event_bus = event_bus

        self._data_dir = data_dir or (Path.home() / ".network_guardian" / "email_react")
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._history_path = self._data_dir / "scan_history.json"
        self._scan_history: list[dict] = self._load_history()

        self._running = False
        self._task: asyncio.Task | None = None
        self._cycle = 0
        self._last_report: EmailReActReport | None = None

        # Build the underlying scanner (no event_bus — we publish from here)
        scan_cfg = EmailScanConfig(
            imap_host=config.imap_host,
            imap_user=config.imap_user,
            imap_password=config.imap_password,
            imap_port=config.imap_port,
            imap_use_ssl=config.imap_use_ssl,
            mailbox=config.mailbox,
            spam_threshold=config.spam_threshold,
            fetch_limit=config.fetch_limit,
            action_mode=config.action_mode,
            spam_folder=config.spam_folder,
        )
        self._scanner = EmailScanner(scan_cfg)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def last_report(self) -> EmailReActReport | None:
        return self._last_report

    @property
    def is_running(self) -> bool:
        return self._running

    async def run_cycle(self) -> EmailReActReport:
        """Execute one full Observe → Reason → Act → Learn cycle."""
        self._cycle += 1
        cycle = self._cycle
        report_id = uuid.uuid4().hex[:12]
        steps: list[ReActStep] = []

        def _step(phase: str, thought: str, detail: Any = None) -> None:
            s = ReActStep(phase=phase, thought=thought, detail=detail)
            steps.append(s)
            logger.info("[%s] %s", phase.upper(), thought)

        # ---- OBSERVE ------------------------------------------------
        _step("observe", f"Starting email scan — cycle #{cycle} "
              f"({self._cfg.imap_user}@{self._cfg.imap_host})")

        scan_results: list[EmailScanResult] = await asyncio.to_thread(
            self._scanner.scan_once
        )

        total     = len(scan_results)
        flagged   = [r for r in scan_results if r.flagged]
        n_flagged = len(flagged)

        _step("observe",
              f"Scan complete: {total} messages fetched, {n_flagged} flagged",
              {"total": total, "flagged": n_flagged,
               "spam": sum(1 for r in flagged if r.spam.is_spam),
               "malware": sum(1 for r in flagged if r.malware.is_infected)})

        obs = {
            "imap_host":       self._cfg.imap_host,
            "mailbox":         self._cfg.mailbox,
            "messages_scanned": total,
            "messages_flagged": n_flagged,
            "cycle":           cycle,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
        }

        # ---- REASON -------------------------------------------------
        _step("reason", "Classifying each flagged message by threat severity and category")

        threats: list[dict] = []
        threat_score = 0.0

        for r in flagged:
            sev, cat = _classify_result(r)
            threat_score += _RISK_SCORES.get(sev, 3.0)
            threats.append({
                "title":      f"Flagged email from {r.sender}",
                "severity":   sev,
                "category":   cat,
                "subject":    r.subject,
                "sender":     r.sender,
                "message_id": r.message_id,
                "spam":       r.spam.is_spam,
                "spam_score": r.spam.score,
                "malware":    r.malware.is_infected,
                "signature":  r.malware.signature,
                "timestamp":  r.timestamp.isoformat(),
                "action_taken": getattr(r, "action_taken", "none"),
                "resolved":   False,
            })

        threat_score = min(100.0, threat_score)

        if threat_score == 0:
            risk_level = "low"
        elif threat_score < 30:
            risk_level = "medium"
        elif threat_score < 60:
            risk_level = "high"
        else:
            risk_level = "critical"

        _step("reason",
              f"Risk assessment: score={threat_score:.0f}/100, level={risk_level.upper()}, "
              f"threats={len(threats)}",
              {"risk_level": risk_level, "threat_score": threat_score,
               "threats": len(threats)})

        # ---- ACT ----------------------------------------------------
        actions: list[dict] = []
        recommendations: list[str] = []

        if threats:
            mode = self._cfg.action_mode
            _step("act", f"Executing protective response for {len(threats)} flagged message(s) (mode={mode})")

            for t in threats:
                imap_action = t.get("action_taken", "none")
                t["action_taken"] = imap_action
                human_action = imap_action if imap_action != "none" else "alert_and_log"
                actions.append({
                    "action":  f"Flagged: {t['sender']} — {t['subject'][:60]}",
                    "detail":  (
                        f"Category: {t['category']} | Severity: {t['severity']} | "
                        f"Spam score: {t['spam_score']:.1f} | "
                        f"Malware: {t['signature'] or 'none'} | "
                        f"IMAP action: {human_action}"
                    ),
                    "success": True,
                })
                if t["malware"]:
                    if "deleted" in imap_action:
                        recommendations.append(
                            f"MALWARE DELETED — Message from {t['sender']} "
                            f"(signature: {t['signature']}) was permanently removed."
                        )
                    else:
                        recommendations.append(
                            f"MALWARE — Do not open attachments from {t['sender']} "
                            f"(signature: {t['signature']}). Delete immediately."
                        )
                elif t["spam"]:
                    if "moved_to:" in imap_action:
                        folder = imap_action.split("moved_to:", 1)[1]
                        recommendations.append(
                            f"SPAM MOVED — Message from {t['sender']} "
                            f"(score: {t['spam_score']:.1f}) moved to {folder}."
                        )
                    elif "deleted" in imap_action:
                        recommendations.append(
                            f"SPAM DELETED — Message from {t['sender']} "
                            f"(score: {t['spam_score']:.1f}) permanently removed."
                        )
                    else:
                        recommendations.append(
                            f"SPAM/PHISHING — Mark as spam and block sender: {t['sender']} "
                            f"(score: {t['spam_score']:.1f})"
                        )

            # Publish to event bus
            if self.event_bus:
                await self._publish_event(threats, risk_level, threat_score)
                _step("act", "Published email threat event to Network Guardian event bus")

        else:
            _step("act", "No threats found — mailbox is clean")

        # Universal recommendations
        if risk_level in ("high", "critical"):
            recommendations.append(
                "Consider enabling server-side spam filtering (e.g. Gmail filters, "
                "Proofpoint, or Mimecast) for additional protection."
            )
            recommendations.append(
                "Review sender reputation and consider adding malicious domains to a "
                "blocklist at the mail gateway level."
            )
        if not threats:
            recommendations.append(
                "Mailbox is clean. Maintain regular scan schedule and keep "
                "SpamAssassin rules up to date (sa-update)."
            )

        # ---- LEARN --------------------------------------------------
        _step("learn", "Persisting scan results to history for trend analysis")
        self._save_history(threats, risk_level, threat_score, total)

        # Trend insight
        recent = self._scan_history[-10:]
        avg_score = (
            sum(h["threat_score"] for h in recent) / len(recent)
            if recent else 0.0
        )
        trend = "rising" if threat_score > avg_score * 1.2 else "stable"
        _step("learn",
              f"Trend: {trend} (cycle avg={avg_score:.1f}, this cycle={threat_score:.1f})",
              {"trend": trend, "avg_score": avg_score})

        # Build report
        report = EmailReActReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            cycle=cycle,
            risk_level=risk_level,
            threat_score=threat_score,
            messages_scanned=total,
            messages_flagged=n_flagged,
            threats=threats,
            actions=actions,
            recommendations=recommendations,
            observations=obs,
            react_steps=[s.to_dict() for s in steps],
        )

        # PDF
        should_pdf = (
            self._cfg.generate_pdf == "always"
            or (self._cfg.generate_pdf == "on_threat" and threats)
        )
        if should_pdf:
            report.pdf_path = self._generate_pdf(report)
            if report.pdf_path:
                _step("act", f"PDF report saved: {report.pdf_path}")

        self._last_report = report
        logger.info(
            "Email ReAct cycle #%d complete — risk=%s score=%.0f "
            "scanned=%d flagged=%d",
            cycle, risk_level.upper(), threat_score, total, n_flagged,
        )
        return report

    async def run(self) -> None:
        """Autonomous async loop — runs run_cycle() every interval_secs."""
        self._running = True
        logger.info(
            "EmailReActAgent started — %s  interval=%ds  generate_pdf=%s",
            self._cfg.imap_user, int(self._cfg.interval_secs), self._cfg.generate_pdf,
        )
        try:
            while self._running:
                try:
                    await self.run_cycle()
                except Exception as exc:
                    logger.error("Email ReAct cycle error: %s", exc, exc_info=True)
                await asyncio.sleep(self._cfg.interval_secs)
        finally:
            self._running = False
            logger.info("EmailReActAgent stopped")

    def start(self) -> None:
        """Schedule the autonomous loop on the running event loop."""
        try:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self.run())
            logger.info("EmailReActAgent background task created")
        except RuntimeError:
            logger.warning(
                "EmailReActAgent.start() called without a running event loop; "
                "use 'await agent.run()' instead."
            )

    def stop(self) -> None:
        """Signal the autonomous loop to stop after the current cycle."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("EmailReActAgent stop requested")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_history(self) -> list[dict]:
        if self._history_path.exists():
            try:
                with open(self._history_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_history(
        self,
        threats: list[dict],
        risk_level: str,
        threat_score: float,
        messages_scanned: int,
    ) -> None:
        entry = {
            "cycle":           self._cycle,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "risk_level":      risk_level,
            "threat_score":    threat_score,
            "messages_scanned": messages_scanned,
            "threats_found":   len(threats),
            "threats":         threats,
        }
        self._scan_history.append(entry)
        # Keep last 500 cycles
        if len(self._scan_history) > 500:
            self._scan_history = self._scan_history[-500:]
        tmp = self._history_path.with_suffix(".tmp")
        try:
            with open(tmp, "w") as f:
                json.dump(self._scan_history, f, indent=2)
            tmp.replace(self._history_path)
        except OSError as e:
            logger.error("Failed to save scan history: %s", e)

    # ------------------------------------------------------------------
    # Event bus
    # ------------------------------------------------------------------

    async def _publish_event(
        self,
        threats: list[dict],
        risk_level: str,
        threat_score: float,
    ) -> None:
        try:
            from network_guardian.core.events import Event
            await self.event_bus.publish(Event(
                topic="email.react.threat_detected",
                data={
                    "risk_level":   risk_level,
                    "threat_score": threat_score,
                    "threats":      len(threats),
                    "cycle":        self._cycle,
                    "mailbox":      self._cfg.mailbox,
                    "imap_host":    self._cfg.imap_host,
                    "details":      threats[:10],   # cap payload size
                },
            ))
        except Exception as e:
            logger.debug("Event bus publish skipped: %s", e)

    # ------------------------------------------------------------------
    # PDF report
    # ------------------------------------------------------------------

    def _generate_pdf(self, report: EmailReActReport) -> str | None:
        try:
            from network_guardian.agent.pdf_reporter import generate_react_pdf
            pdf_dir = self._data_dir / "pdf_reports"
            pdf_dir.mkdir(parents=True, exist_ok=True)
            # Mirror to project pdf_reports/ as well
            proj_dir = Path("pdf_reports")
            proj_dir.mkdir(exist_ok=True)

            filename = f"email_react_{report.report_id}.pdf"
            out_path = pdf_dir / filename

            generate_react_pdf(
                report_id=report.report_id,
                report_type="Email Threat Report",
                risk_level=report.risk_level,
                threat_score=report.threat_score,
                threats_found=len(report.threats),
                actions_taken=len(report.actions),
                observations=report.observations,
                react_steps=report.react_steps,
                threats=report.threats,
                actions=report.actions,
                recommendations=report.recommendations,
                out_path=str(out_path),
            )
            # Copy to project mirror
            import shutil
            shutil.copy2(out_path, proj_dir / filename)
            return str(out_path)
        except Exception as e:
            logger.warning("PDF generation failed: %s", e)
            return None


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import getpass as _getpass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    print("=== Network Guardian — Email ReAct Agent ===\n")
    host     = input("IMAP host (e.g. imap.gmail.com): ").strip()
    user     = input("Email address: ").strip()
    password = _getpass.getpass("Password / app password: ")
    mailbox  = input("Mailbox [INBOX]: ").strip() or "INBOX"
    interval = input("Scan interval seconds [300]: ").strip()
    try:
        interval_secs = float(interval) if interval else 300.0
    except ValueError:
        interval_secs = 300.0

    cfg = EmailReActConfig(
        imap_host=host,
        imap_user=user,
        imap_password=password,
        mailbox=mailbox,
        interval_secs=interval_secs,
    )

    agent = EmailReActAgent(cfg)

    mode = input("\nRun once or loop? (once/loop) [once]: ").strip().lower() or "once"
    if mode == "loop":
        print(f"\nStarting autonomous loop — scanning every {interval_secs:.0f}s. Ctrl+C to stop.\n")
        asyncio.run(agent.run())
    else:
        report = asyncio.run(agent.run_cycle())
        print(f"\n{'─'*60}")
        print(f"  Risk Level  : {report.risk_level.upper()}")
        print(f"  Threat Score: {report.threat_score:.0f}/100")
        print(f"  Scanned     : {report.messages_scanned} messages")
        print(f"  Flagged     : {report.messages_flagged} messages")
        if report.pdf_path:
            print(f"  PDF Report  : {report.pdf_path}")
        print(f"{'─'*60}\n")
        for r in report.recommendations:
            print(f"  • {r}")
        print()


if __name__ == "__main__":
    main()
