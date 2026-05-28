"""
Network Guardian — Email Protection Scanner

Connects to an IMAP mailbox, fetches unseen messages, and runs each
through two independent analysis layers:

  1. SpamAssassin (spamc CLI) — spam/phishing scoring
  2. ClamAV (clamscan CLI) — malware / virus detection

Both tools are invoked as subprocesses so there are no additional Python
packages required beyond the standard library.  If a tool is not installed
on the host the corresponding check is skipped and flagged in the result.

Typical usage::

    import asyncio
    from network_guardian.agent.email_scanner import EmailScanner, EmailScanConfig

    config = EmailScanConfig(
        imap_host="imap.gmail.com",
        imap_user="you@gmail.com",
        imap_password="app-password",
    )
    scanner = EmailScanner(config)
    asyncio.run(scanner.run())
"""

from __future__ import annotations

import asyncio
import email
import imaplib
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian.agent.email_scanner")


# ---------------------------------------------------------------------------
# Provider spam-folder presets
# ---------------------------------------------------------------------------

_SPAM_FOLDER_PRESETS: dict[str, str] = {
    "imap.gmail.com":         "[Gmail]/Spam",
    "imap.googlemail.com":    "[Gmail]/Spam",
    "outlook.office365.com":  "Junk",
    "imap-mail.outlook.com":  "Junk",
    "imap.mail.yahoo.com":    "Bulk Mail",
    "imap.mail.me.com":       "Junk",       # iCloud
    "imap.zoho.com":          "Spam",
    "imap.fastmail.com":      "Spam",
}
# ---------------------------------------------------------------------------

@dataclass
class EmailScanConfig:
    """Connection and scanning parameters."""
    imap_host: str
    imap_user: str
    imap_password: str
    imap_port: int = 993
    imap_use_ssl: bool = True
    mailbox: str = "INBOX"
    # Spam score threshold above which a message is flagged (SpamAssassin default: 5.0)
    spam_threshold: float = 5.0
    # Maximum number of unseen messages to fetch per run
    fetch_limit: int = 50
    # Active protection mode:
    #   "monitor"       — detect only, no IMAP changes (default, safe)
    #   "move_spam"     — move spam to spam_folder; delete malware
    #   "delete_all"    — delete spam and malware (permanent after expunge)
    action_mode: str = "monitor"
    # Destination folder for spam when action_mode="move_spam".
    # Leave as empty string to auto-detect from imap_host using provider presets.
    spam_folder: str = ""

    def resolved_spam_folder(self) -> str:
        """Return the spam folder, auto-detecting from provider presets if not set."""
        if self.spam_folder:
            return self.spam_folder
        return _SPAM_FOLDER_PRESETS.get(self.imap_host.lower(), "Spam")


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SpamResult:
    available: bool          # False if spamc is not installed
    score: float = 0.0
    threshold: float = 5.0
    is_spam: bool = False
    report_summary: str = ""


@dataclass
class MalwareResult:
    available: bool          # False if clamscan is not installed
    is_infected: bool = False
    signature: str = ""      # name of the detected signature, if any
    raw_output: str = ""


@dataclass
class EmailScanResult:
    message_id: str
    subject: str
    sender: str
    timestamp: datetime
    spam: SpamResult
    malware: MalwareResult
    flagged: bool = False       # True if spam OR malware detected
    action_taken: str = "none" # IMAP action performed (none/deleted/moved_to:...)

    def __post_init__(self) -> None:
        self.flagged = self.spam.is_spam or self.malware.is_infected


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _spamc_available() -> bool:
    return shutil.which("spamc") is not None


def _clamscan_available() -> bool:
    return shutil.which("clamscan") is not None


def _run_spamassassin(raw_bytes: bytes, threshold: float) -> SpamResult:
    """Pipe the raw message through spamc and parse the result."""
    if not _spamc_available():
        return SpamResult(available=False)

    try:
        proc = subprocess.run(
            ["spamc", "-c"],          # -c: output score/threshold line; exit 1 if spam
            input=raw_bytes,
            capture_output=True,
            timeout=30,
        )
        # spamc -c writes "<score>/<threshold>\n" to stdout
        output = proc.stdout.decode(errors="replace").strip()
        is_spam = proc.returncode == 1
        score, threshold_parsed = 0.0, threshold
        if "/" in output:
            parts = output.split("/")
            try:
                score = float(parts[0].strip())
                threshold_parsed = float(parts[1].strip())
            except ValueError:
                pass
        return SpamResult(
            available=True,
            score=score,
            threshold=threshold_parsed,
            is_spam=is_spam or score >= threshold,
            report_summary=output,
        )
    except subprocess.TimeoutExpired:
        logger.warning("spamc timed out")
        return SpamResult(available=True, report_summary="timeout")
    except OSError as e:
        logger.error("spamc error: %s", e)
        return SpamResult(available=False, report_summary=str(e))


def _run_clamscan(raw_bytes: bytes) -> MalwareResult:
    """Write the message to a temp file and scan it with clamscan."""
    if not _clamscan_available():
        return MalwareResult(available=False)

    try:
        with tempfile.NamedTemporaryFile(
            prefix="ng_email_", suffix=".eml", delete=False
        ) as tmp:
            tmp.write(raw_bytes)
            tmp_path = Path(tmp.name)

        try:
            proc = subprocess.run(
                ["clamscan", "--no-summary", str(tmp_path)],
                capture_output=True,
                timeout=60,
            )
            output = proc.stdout.decode(errors="replace").strip()
            # clamscan exits 1 when a virus is found; line format:
            # /path/to/file: Eicar-Test-Signature FOUND
            is_infected = proc.returncode == 1
            signature = ""
            if is_infected:
                for line in output.splitlines():
                    if "FOUND" in line:
                        # Extract signature name between ": " and " FOUND"
                        try:
                            signature = line.split(": ", 1)[1].replace(" FOUND", "").strip()
                        except IndexError:
                            signature = "unknown"
                        break
            return MalwareResult(
                available=True,
                is_infected=is_infected,
                signature=signature,
                raw_output=output,
            )
        finally:
            tmp_path.unlink(missing_ok=True)

    except subprocess.TimeoutExpired:
        logger.warning("clamscan timed out")
        return MalwareResult(available=True, raw_output="timeout")
    except OSError as e:
        logger.error("clamscan error: %s", e)
        return MalwareResult(available=False, raw_output=str(e))


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class EmailScanner:
    """Fetch unseen emails via IMAP and scan each for spam and malware."""

    def __init__(
        self,
        config: EmailScanConfig,
        event_bus: Any | None = None,
    ) -> None:
        self._cfg = config
        self._bus = event_bus

    # ------------------------------------------------------------------
    # IMAP connection
    # ------------------------------------------------------------------

    def _connect(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """Open an authenticated IMAP connection."""
        if self._cfg.imap_use_ssl:
            conn = imaplib.IMAP4_SSL(self._cfg.imap_host, self._cfg.imap_port)
        else:
            conn = imaplib.IMAP4(self._cfg.imap_host, self._cfg.imap_port)
        conn.login(self._cfg.imap_user, self._cfg.imap_password)
        return conn

    def _fetch_unseen(
        self, conn: imaplib.IMAP4 | imaplib.IMAP4_SSL
    ) -> list[tuple[str, bytes]]:
        """Select the mailbox and return (uid, raw_bytes) for unseen messages."""
        readonly = self._cfg.action_mode == "monitor"
        conn.select(f'"{self._cfg.mailbox}"', readonly=readonly)
        _, data = conn.uid("search", None, "UNSEEN")
        uids = data[0].split() if data and data[0] else []
        uids = uids[-self._cfg.fetch_limit:]   # newest N only

        messages: list[tuple[str, bytes]] = []
        for uid in uids:
            _, msg_data = conn.uid("fetch", uid, "(RFC822)")
            for part in msg_data:
                if isinstance(part, tuple):
                    messages.append((uid.decode(), part[1]))
        return messages

    def _take_action(
        self,
        conn: imaplib.IMAP4 | imaplib.IMAP4_SSL,
        uid: str,
        result: "EmailScanResult",
    ) -> str:
        """Perform an IMAP action on a flagged message. Returns action description."""
        if self._cfg.action_mode == "monitor" or not result.flagged:
            return "none"

        uid_bytes = uid.encode()

        try:
            if result.malware.is_infected or self._cfg.action_mode == "delete_all":
                # Mark as deleted and expunge — permanent removal
                conn.uid("store", uid_bytes, "+FLAGS", "(\\Deleted)")
                conn.expunge()
                action = "deleted"
                logger.warning(
                    "DELETED uid=%s from=%s — malware=%s spam=%s",
                    uid, result.sender,
                    result.malware.signature or "yes" if result.malware.is_infected else "no",
                    result.spam.is_spam,
                )
            elif result.spam.is_spam and self._cfg.action_mode == "move_spam":
                # Move to spam folder via IMAP COPY + delete original
                spam_folder = self._cfg.resolved_spam_folder()
                conn.uid("copy", uid_bytes, spam_folder)
                conn.uid("store", uid_bytes, "+FLAGS", "(\\Deleted)")
                conn.expunge()
                action = f"moved_to:{spam_folder}"
                logger.warning(
                    "MOVED uid=%s from=%s to %s (spam score=%.1f)",
                    uid, result.sender, spam_folder, result.spam.score,
                )
            else:
                action = "none"
        except Exception as e:
            logger.error("IMAP action failed for uid=%s: %s", uid, e)
            action = f"error:{e}"

        return action

    # ------------------------------------------------------------------
    # Per-message scanning
    # ------------------------------------------------------------------

    def _scan_message(self, uid: str, raw: bytes) -> EmailScanResult:
        """Parse headers, run SpamAssassin, run ClamAV, return result."""
        msg = email.message_from_bytes(raw)
        subject = msg.get("Subject", "(no subject)")
        sender = msg.get("From", "(unknown)")
        date_str = msg.get("Date", "")
        message_id = msg.get("Message-ID", uid)

        try:
            from email.utils import parsedate_to_datetime
            ts = parsedate_to_datetime(date_str) if date_str else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        spam_result = _run_spamassassin(raw, self._cfg.spam_threshold)
        malware_result = _run_clamscan(raw)

        result = EmailScanResult(
            message_id=message_id,
            subject=subject,
            sender=sender,
            timestamp=ts,
            spam=spam_result,
            malware=malware_result,
        )

        level = logging.WARNING if result.flagged else logging.INFO
        logger.log(
            level,
            "Email uid=%s | from=%s | spam=%s(%.1f) | malware=%s(%s) | flagged=%s",
            uid,
            sender,
            "YES" if spam_result.is_spam else "no",
            spam_result.score,
            "YES" if malware_result.is_infected else "no",
            malware_result.signature or "-",
            result.flagged,
        )
        return result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_once(self) -> list[EmailScanResult]:
        """Synchronous: connect, scan unseen messages, act on threats, disconnect."""
        try:
            conn = self._connect()
        except imaplib.IMAP4.error as e:
            logger.error("IMAP connection failed: %s", e)
            return []

        try:
            messages = self._fetch_unseen(conn)
        except Exception as e:
            logger.error("Failed to fetch messages: %s", e)
            return []

        results: list[EmailScanResult] = []
        for uid, raw in messages:
            result = self._scan_message(uid, raw)
            results.append(result)
            if result.flagged:
                result.action_taken = self._take_action(conn, uid, result)
                if self._bus is not None:
                    self._publish_event(result)

        try:
            conn.logout()
        except Exception:
            pass

        flagged = sum(1 for r in results if r.flagged)
        logger.info(
            "Email scan complete: %d messages scanned, %d flagged (mode=%s)",
            len(results), flagged, self._cfg.action_mode,
        )
        return results

    async def run(self, interval_seconds: float = 300.0) -> None:
        """Async loop: scan every `interval_seconds` (default 5 min) indefinitely."""
        logger.info(
            "Email scanner started — %s@%s:%d  mailbox=%s  interval=%ds",
            self._cfg.imap_user,
            self._cfg.imap_host,
            self._cfg.imap_port,
            self._cfg.mailbox,
            int(interval_seconds),
        )
        while True:
            await asyncio.get_event_loop().run_in_executor(None, self.scan_once)
            await asyncio.sleep(interval_seconds)

    # ------------------------------------------------------------------
    # Event bus integration
    # ------------------------------------------------------------------

    def _publish_event(self, result: EmailScanResult) -> None:
        """Publish a threat event to the Network Guardian event bus."""
        try:
            from network_guardian.core.events import Event
            detail: dict[str, Any] = {
                "message_id": result.message_id,
                "sender": result.sender,
                "subject": result.subject,
                "spam": result.spam.is_spam,
                "spam_score": result.spam.score,
                "malware": result.malware.is_infected,
                "malware_signature": result.malware.signature,
            }
            event = Event(
                topic="email.threat_detected",
                data=detail,
            )
            if asyncio.get_event_loop().is_running():
                asyncio.ensure_future(self._bus.publish(event))
        except Exception as e:
            logger.debug("Event bus publish skipped: %s", e)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import getpass as _getpass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    print("=== Network Guardian — Email Protection Scanner ===\n")
    host     = input("IMAP host (e.g. imap.gmail.com): ").strip()
    user     = input("Email address: ").strip()
    password = _getpass.getpass("Password / app password: ")
    mailbox  = input("Mailbox [INBOX]: ").strip() or "INBOX"

    print("\nProtection mode:")
    print("  monitor    — scan and report only (no changes to mailbox)")
    print("  move_spam  — move spam to Junk/Spam folder; delete malware")
    print("  delete_all — permanently delete all spam and malware")
    mode = input("Mode [monitor]: ").strip().lower() or "monitor"
    if mode not in ("monitor", "move_spam", "delete_all"):
        print(f"Unknown mode '{mode}', defaulting to monitor.")
        mode = "monitor"

    spam_folder = ""
    if mode == "move_spam":
        preset = _SPAM_FOLDER_PRESETS.get(host.lower(), "Spam")
        spam_folder = input(f"Spam folder [{preset}]: ").strip() or preset

    cfg = EmailScanConfig(
        imap_host=host,
        imap_user=user,
        imap_password=password,
        mailbox=mailbox,
        action_mode=mode,
        spam_folder=spam_folder,
    )

    if not _spamc_available():
        print("\n[!] spamc not found — SpamAssassin checks will be skipped.")
        print("    Install: brew install spamassassin  OR  apt install spamassassin\n")
    if not _clamscan_available():
        print("\n[!] clamscan not found — ClamAV malware checks will be skipped.")
        print("    Install: brew install clamav  OR  apt install clamav\n")

    if mode != "monitor":
        confirm = input(
            f"\n[!] Active mode '{mode}' will modify your mailbox. Continue? (yes/no): "
        ).strip().lower()
        if confirm != "yes":
            print("Aborted.")
            return

    scanner = EmailScanner(cfg)
    results = scanner.scan_once()

    if not results:
        print("No unseen messages found or connection failed.")
        return

    print(f"\n{'─' * 80}")
    print(f"{'UID':<10} {'Spam':>6} {'Score':>6}  {'Malware':<24}  {'Action':<20}  Subject")
    print(f"{'─' * 80}")
    for r in results:
        spam_tag  = "SPAM" if r.spam.is_spam else "ok"
        mal_tag   = f"VIRUS:{r.malware.signature[:18]}" if r.malware.is_infected else "clean"
        score_str = f"{r.spam.score:.1f}" if r.spam.available else "N/A"
        act_tag   = r.action_taken if r.action_taken != "none" else "-"
        print(
            f"{r.message_id[-9:]:<10} {spam_tag:>6} {score_str:>6}  "
            f"{mal_tag:<24}  {act_tag:<20}  {r.subject[:30]}"
        )
    print(f"{'─' * 80}")
    flagged = sum(1 for r in results if r.flagged)
    acted  = sum(1 for r in results if r.action_taken not in ("none", ""))
    print(f"\n{len(results)} messages scanned — {flagged} flagged — {acted} actions taken\n")


if __name__ == "__main__":
    main()
