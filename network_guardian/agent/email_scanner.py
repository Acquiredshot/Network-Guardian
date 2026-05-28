"""
Network Guardian — Email Protection Scanner
Backend: uses OpenRouter API (gpt-oss-120b) for AI-powered threat analysis.
SpamAssassin (spamc) and ClamAV (clamscan) for local scanning.
SQLite for persistent logging.
"""

from __future__ import annotations

import asyncio
import email
import imaplib
import json
import logging
import shutil
import sqlite3
import subprocess
import tempfile
import urllib.request
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian")

DB_PATH = Path("network_guardian.db")

# ── OpenRouter config ─────────────────────────────────────────────────────────
OPENROUTER_API_KEY = "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"   # ← paste your key here
OPENROUTER_MODEL   = "gpt-oss-120b"
OPENROUTER_URL     = "https://openrouter.ai/api/v1/chat/completions"

_SPAM_FOLDER_PRESETS = {
    "imap.gmail.com":        "[Gmail]/Spam",
    "imap.googlemail.com":   "[Gmail]/Spam",
    "outlook.office365.com": "Junk",
    "imap-mail.outlook.com": "Junk",
    "imap.mail.yahoo.com":   "Bulk Mail",
    "imap.mail.me.com":      "Junk",
    "imap.zoho.com":         "Spam",
    "imap.fastmail.com":     "Spam",
}


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class EmailScanConfig:
    imap_host: str
    imap_user: str
    imap_password: str
    imap_port: int = 993
    imap_use_ssl: bool = True
    mailbox: str = "INBOX"
    spam_threshold: float = 5.0
    fetch_limit: int = 50
    action_mode: str = "monitor"   # monitor | move_spam | delete_all
    spam_folder: str = ""

    def resolved_spam_folder(self) -> str:
        if self.spam_folder:
            return self.spam_folder
        return _SPAM_FOLDER_PRESETS.get(self.imap_host.lower(), "Spam")


@dataclass
class SpamResult:
    available: bool
    score: float = 0.0
    threshold: float = 5.0
    is_spam: bool = False
    report_summary: str = ""


@dataclass
class MalwareResult:
    available: bool
    is_infected: bool = False
    signature: str = ""
    raw_output: str = ""


@dataclass
class AIAnalysis:
    threat_type: str = "unknown"        # phishing | ceo_fraud | invoice_scam | malware | clean | unknown
    confidence: float = 0.0             # 0.0 – 1.0
    explanation: str = ""
    recommended_action: str = "review"  # allow | quarantine | delete | review
    risk_level: str = "low"             # low | medium | high | critical


@dataclass
class EmailScanResult:
    uid: str
    message_id: str
    subject: str
    sender: str
    timestamp: datetime
    spam: SpamResult
    malware: MalwareResult
    ai: AIAnalysis
    flagged: bool = False
    action_taken: str = "none"

    def __post_init__(self) -> None:
        self.flagged = self.spam.is_spam or self.malware.is_infected or self.ai.risk_level in ("high", "critical")


# ── Database ──────────────────────────────────────────────────────────────────

def init_db(path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            uid          TEXT,
            message_id   TEXT,
            subject      TEXT,
            sender       TEXT,
            timestamp    TEXT,
            spam_score   REAL,
            is_spam      INTEGER,
            is_infected  INTEGER,
            malware_sig  TEXT,
            threat_type  TEXT,
            risk_level   TEXT,
            confidence   REAL,
            explanation  TEXT,
            action_taken TEXT,
            flagged      INTEGER,
            scanned_at   TEXT
        )
    """)
    conn.commit()
    return conn


def save_result(conn: sqlite3.Connection, r: EmailScanResult) -> None:
    conn.execute("""
        INSERT INTO scan_results
        (uid,message_id,subject,sender,timestamp,spam_score,is_spam,
         is_infected,malware_sig,threat_type,risk_level,confidence,
         explanation,action_taken,flagged,scanned_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        r.uid, r.message_id, r.subject, r.sender,
        r.timestamp.isoformat(),
        r.spam.score, int(r.spam.is_spam),
        int(r.malware.is_infected), r.malware.signature,
        r.ai.threat_type, r.ai.risk_level, r.ai.confidence,
        r.ai.explanation, r.action_taken, int(r.flagged),
        datetime.now(timezone.utc).isoformat(),
    ))
    conn.commit()


def get_stats(conn: sqlite3.Connection) -> dict:
    today = datetime.now(timezone.utc).date().isoformat()
    row = conn.execute("""
        SELECT
            COUNT(*) as total,
            SUM(flagged) as flagged,
            SUM(is_spam) as spam,
            SUM(is_infected) as malware
        FROM scan_results
        WHERE scanned_at >= ?
    """, (today,)).fetchone()
    return {
        "total": row[0] or 0,
        "flagged": row[1] or 0,
        "spam": row[2] or 0,
        "malware": row[3] or 0,
    }


def get_recent(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute("""
        SELECT uid,subject,sender,spam_score,is_spam,is_infected,
               malware_sig,threat_type,risk_level,action_taken,flagged,scanned_at
        FROM scan_results
        ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    keys = ["uid","subject","sender","spam_score","is_spam","is_infected",
            "malware_sig","threat_type","risk_level","action_taken","flagged","scanned_at"]
    return [dict(zip(keys, r)) for r in rows]


def get_weekly_volume(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT DATE(scanned_at) as day,
               COUNT(*) as total,
               SUM(flagged) as flagged
        FROM scan_results
        WHERE scanned_at >= DATE('now', '-7 days')
        GROUP BY day ORDER BY day
    """).fetchall()
    return [{"day": r[0], "total": r[1], "flagged": r[2]} for r in rows]


# ── OpenRouter AI analysis ────────────────────────────────────────────────────

def _ai_analyze(subject: str, sender: str, body_preview: str) -> AIAnalysis:
    """Call OpenRouter gpt-oss-120b to classify the email threat."""
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == "YOUR_OPENROUTER_API_KEY_HERE":
        return AIAnalysis(threat_type="unknown", explanation="AI key not configured.")

    prompt = f"""You are an expert email security analyst. Analyze this email and respond ONLY with valid JSON.

Email:
- Subject: {subject}
- From: {sender}
- Body preview: {body_preview[:500]}

Respond with this exact JSON structure:
{{
  "threat_type": "phishing|ceo_fraud|invoice_scam|malware|newsletter_spam|clean|unknown",
  "confidence": 0.0,
  "risk_level": "low|medium|high|critical",
  "explanation": "one sentence explanation",
  "recommended_action": "allow|quarantine|delete|review"
}}"""

    payload = json.dumps({
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 300,
        "temperature": 0.1,
    }).encode()

    req = urllib.request.Request(
        OPENROUTER_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://network-guardian.local",
            "X-Title": "Network Guardian",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        text = data["choices"][0]["message"]["content"].strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:-1])
        result = json.loads(text)
        return AIAnalysis(
            threat_type=result.get("threat_type", "unknown"),
            confidence=float(result.get("confidence", 0.0)),
            risk_level=result.get("risk_level", "low"),
            explanation=result.get("explanation", ""),
            recommended_action=result.get("recommended_action", "review"),
        )
    except Exception as e:
        logger.error("AI analysis failed: %s", e)
        return AIAnalysis(threat_type="unknown", explanation=str(e))


# ── SpamAssassin & ClamAV ────────────────────────────────────────────────────

def _run_spamassassin(raw: bytes, threshold: float) -> SpamResult:
    if not shutil.which("spamc"):
        return SpamResult(available=False)
    try:
        proc = subprocess.run(["spamc", "-c"], input=raw, capture_output=True, timeout=30)
        out = proc.stdout.decode(errors="replace").strip()
        score, thr = 0.0, threshold
        if "/" in out:
            parts = out.split("/")
            try:
                score = float(parts[0].strip())
                thr   = float(parts[1].strip())
            except ValueError:
                pass
        return SpamResult(available=True, score=score, threshold=thr,
                          is_spam=proc.returncode == 1 or score >= threshold,
                          report_summary=out)
    except Exception as e:
        return SpamResult(available=False, report_summary=str(e))


def _run_clamscan(raw: bytes) -> MalwareResult:
    if not shutil.which("clamscan"):
        return MalwareResult(available=False)
    try:
        with tempfile.NamedTemporaryFile(prefix="ng_", suffix=".eml", delete=False) as f:
            f.write(raw)
            tmp = Path(f.name)
        proc = subprocess.run(["clamscan", "--no-summary", str(tmp)],
                              capture_output=True, timeout=60)
        out = proc.stdout.decode(errors="replace").strip()
        sig = ""
        if proc.returncode == 1:
            for line in out.splitlines():
                if "FOUND" in line:
                    try: sig = line.split(": ", 1)[1].replace(" FOUND", "").strip()
                    except IndexError: sig = "unknown"
                    break
        tmp.unlink(missing_ok=True)
        return MalwareResult(available=True, is_infected=proc.returncode == 1,
                             signature=sig, raw_output=out)
    except Exception as e:
        return MalwareResult(available=False, raw_output=str(e))


# ── Main Scanner ──────────────────────────────────────────────────────────────

class EmailScanner:
    def __init__(self, config: EmailScanConfig, db_conn: sqlite3.Connection | None = None):
        self._cfg = config
        self._db = db_conn or init_db()

    def _connect(self):
        if self._cfg.imap_use_ssl:
            conn = imaplib.IMAP4_SSL(self._cfg.imap_host, self._cfg.imap_port)
        else:
            conn = imaplib.IMAP4(self._cfg.imap_host, self._cfg.imap_port)
        conn.login(self._cfg.imap_user, self._cfg.imap_password)
        return conn

    def _fetch_unseen(self, conn) -> list[tuple[str, bytes]]:
        readonly = self._cfg.action_mode == "monitor"
        conn.select(f'"{self._cfg.mailbox}"', readonly=readonly)
        _, data = conn.uid("search", None, "UNSEEN")
        uids = (data[0].split() if data and data[0] else [])[-self._cfg.fetch_limit:]
        messages = []
        for uid in uids:
            _, msg_data = conn.uid("fetch", uid, "(RFC822)")
            for part in msg_data:
                if isinstance(part, tuple):
                    messages.append((uid.decode(), part[1]))
        return messages

    def _body_preview(self, msg) -> str:
        preview = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        preview = part.get_payload(decode=True).decode(errors="replace")[:500]
                        break
                    except Exception:
                        pass
        else:
            try:
                preview = msg.get_payload(decode=True).decode(errors="replace")[:500]
            except Exception:
                pass
        return preview

    def _scan_message(self, uid: str, raw: bytes) -> EmailScanResult:
        msg       = email.message_from_bytes(raw)
        subject   = msg.get("Subject", "(no subject)")
        sender    = msg.get("From", "(unknown)")
        date_str  = msg.get("Date", "")
        msg_id    = msg.get("Message-ID", uid)
        preview   = self._body_preview(msg)

        try:
            from email.utils import parsedate_to_datetime
            ts = parsedate_to_datetime(date_str) if date_str else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        spam    = _run_spamassassin(raw, self._cfg.spam_threshold)
        malware = _run_clamscan(raw)
        ai      = _ai_analyze(subject, sender, preview)

        result = EmailScanResult(uid=uid, message_id=msg_id, subject=subject,
                                 sender=sender, timestamp=ts,
                                 spam=spam, malware=malware, ai=ai)
        level = logging.WARNING if result.flagged else logging.INFO
        logger.log(level, "uid=%s from=%s spam=%s(%.1f) malware=%s ai=%s(%s) flagged=%s",
                   uid, sender,
                   "YES" if spam.is_spam else "no", spam.score,
                   "YES" if malware.is_infected else "no",
                   ai.threat_type, ai.risk_level, result.flagged)
        return result

    def _take_action(self, conn, uid: str, result: EmailScanResult) -> str:
        if self._cfg.action_mode == "monitor" or not result.flagged:
            return "none"
        uid_b = uid.encode()
        try:
            if result.malware.is_infected or self._cfg.action_mode == "delete_all":
                conn.uid("store", uid_b, "+FLAGS", "(\\Deleted)")
                conn.expunge()
                return "deleted"
            elif result.spam.is_spam and self._cfg.action_mode == "move_spam":
                folder = self._cfg.resolved_spam_folder()
                conn.uid("copy", uid_b, folder)
                conn.uid("store", uid_b, "+FLAGS", "(\\Deleted)")
                conn.expunge()
                return f"moved_to:{folder}"
        except Exception as e:
            return f"error:{e}"
        return "none"

    def scan_once(self) -> list[EmailScanResult]:
        try:
            conn = self._connect()
        except imaplib.IMAP4.error as e:
            logger.error("IMAP failed: %s", e)
            return []

        try:
            messages = self._fetch_unseen(conn)
        except Exception as e:
            logger.error("Fetch failed: %s", e)
            return []

        results = []
        for uid, raw in messages:
            r = self._scan_message(uid, raw)
            r.action_taken = self._take_action(conn, uid, r)
            save_result(self._db, r)
            results.append(r)

        try:
            conn.logout()
        except Exception:
            pass

        flagged = sum(1 for r in results if r.flagged)
        logger.info("Scan complete: %d scanned, %d flagged (mode=%s)",
                    len(results), flagged, self._cfg.action_mode)
        return results

    async def run(self, interval: float = 300.0) -> None:
        logger.info("Scanner started — %s@%s interval=%ds",
                    self._cfg.imap_user, self._cfg.imap_host, int(interval))
        while True:
            await asyncio.get_event_loop().run_in_executor(None, self.scan_once)
            await asyncio.sleep(interval)

    def get_dashboard_data(self) -> dict:
        return {
            "stats": get_stats(self._db),
            "recent": get_recent(self._db, 20),
            "weekly": get_weekly_volume(self._db),
        }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    import getpass

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s  %(levelname)-8s  %(message)s")

    print("\n╔══════════════════════════════════════════╗")
    print("║   Network Guardian — Email Scanner  v2   ║")
    print("╚══════════════════════════════════════════╝\n")

    host     = input("IMAP host (e.g. imap.gmail.com): ").strip()
    user     = input("Email address: ").strip()
    password = getpass.getpass("App password: ")
    mailbox  = input("Mailbox [INBOX]: ").strip() or "INBOX"

    print("\nMode: monitor | move_spam | delete_all")
    mode = input("Mode [monitor]: ").strip().lower() or "monitor"
    if mode not in ("monitor", "move_spam", "delete_all"):
        mode = "monitor"

    cfg = EmailScanConfig(imap_host=host, imap_user=user,
                          imap_password=password, mailbox=mailbox,
                          action_mode=mode)
    db  = init_db()
    scanner = EmailScanner(cfg, db)
    results = scanner.scan_once()

    if not results:
        print("No unseen messages found.")
        return

    print(f"\n{'─'*90}")
    print(f"{'Subject':<32} {'From':<28} {'Spam':>5} {'Risk':<8} {'AI Type':<16} Action")
    print(f"{'─'*90}")
    for r in results:
        print(f"{r.subject[:30]:<32} {r.sender[:26]:<28} "
              f"{'YES' if r.spam.is_spam else 'no':>5} {r.ai.risk_level:<8} "
              f"{r.ai.threat_type:<16} {r.action_taken}")
    print(f"{'─'*90}")
    print(f"\n{len(results)} scanned — {sum(1 for r in results if r.flagged)} flagged\n")


if __name__ == "__main__":
    main()
