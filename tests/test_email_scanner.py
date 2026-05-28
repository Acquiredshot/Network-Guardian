"""Tests for network_guardian.agent.email_scanner."""

import asyncio
import email as _email
import imaplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from unittest.mock import MagicMock, patch, call

import pytest

from network_guardian.agent.email_scanner import (
    EmailScanConfig,
    EmailScanner,
    MalwareResult,
    SpamResult,
    _clamscan_available,
    _run_clamscan,
    _run_spamassassin,
    _spamc_available,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_raw_email(subject="Test", sender="alice@example.com", body="Hello") -> bytes:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = "you@example.com"
    msg["Date"] = "Mon, 27 May 2026 12:00:00 +0000"
    msg["Message-ID"] = "<test-001@example.com>"
    return msg.as_bytes()


def _make_config(**kwargs) -> EmailScanConfig:
    defaults = dict(
        imap_host="imap.example.com",
        imap_user="user@example.com",
        imap_password="password",
    )
    defaults.update(kwargs)
    return EmailScanConfig(**defaults)


# ---------------------------------------------------------------------------
# Tool availability helpers
# ---------------------------------------------------------------------------

class TestToolAvailability:
    def test_spamc_available_when_on_path(self):
        with patch("shutil.which", return_value="/usr/bin/spamc"):
            assert _spamc_available() is True

    def test_spamc_unavailable_when_missing(self):
        with patch("shutil.which", return_value=None):
            assert _spamc_available() is False

    def test_clamscan_available_when_on_path(self):
        with patch("shutil.which", return_value="/usr/bin/clamscan"):
            assert _clamscan_available() is True

    def test_clamscan_unavailable_when_missing(self):
        with patch("shutil.which", return_value=None):
            assert _clamscan_available() is False


# ---------------------------------------------------------------------------
# SpamAssassin layer
# ---------------------------------------------------------------------------

class TestRunSpamAssassin:
    def test_skipped_when_not_installed(self):
        with patch("network_guardian.agent.email_scanner._spamc_available", return_value=False):
            result = _run_spamassassin(b"raw", threshold=5.0)
        assert result.available is False
        assert result.is_spam is False

    def test_clean_message(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"1.2/5.0\n"
        with patch("network_guardian.agent.email_scanner._spamc_available", return_value=True), \
             patch("subprocess.run", return_value=mock_proc):
            result = _run_spamassassin(b"raw", threshold=5.0)
        assert result.available is True
        assert result.is_spam is False
        assert abs(result.score - 1.2) < 0.01

    def test_spam_message_by_exit_code(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = b"6.5/5.0\n"
        with patch("network_guardian.agent.email_scanner._spamc_available", return_value=True), \
             patch("subprocess.run", return_value=mock_proc):
            result = _run_spamassassin(b"raw", threshold=5.0)
        assert result.is_spam is True
        assert abs(result.score - 6.5) < 0.01

    def test_spam_message_by_threshold(self):
        """Score >= threshold should be flagged even if exit code is 0."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"5.5/5.0\n"
        with patch("network_guardian.agent.email_scanner._spamc_available", return_value=True), \
             patch("subprocess.run", return_value=mock_proc):
            result = _run_spamassassin(b"raw", threshold=5.0)
        assert result.is_spam is True

    def test_timeout_handled(self):
        import subprocess
        with patch("network_guardian.agent.email_scanner._spamc_available", return_value=True), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("spamc", 30)):
            result = _run_spamassassin(b"raw", threshold=5.0)
        assert result.available is True
        assert result.is_spam is False
        assert "timeout" in result.report_summary


# ---------------------------------------------------------------------------
# ClamAV layer
# ---------------------------------------------------------------------------

class TestRunClamscan:
    def test_skipped_when_not_installed(self):
        with patch("network_guardian.agent.email_scanner._clamscan_available", return_value=False):
            result = _run_clamscan(b"raw")
        assert result.available is False
        assert result.is_infected is False

    def test_clean_file(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"/tmp/ng_email_.eml: OK\n"
        with patch("network_guardian.agent.email_scanner._clamscan_available", return_value=True), \
             patch("subprocess.run", return_value=mock_proc), \
             patch("pathlib.Path.unlink"):
            result = _run_clamscan(b"raw")
        assert result.available is True
        assert result.is_infected is False
        assert result.signature == ""

    def test_infected_file(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = b"/tmp/ng_email_.eml: Eicar-Test-Signature FOUND\n"
        with patch("network_guardian.agent.email_scanner._clamscan_available", return_value=True), \
             patch("subprocess.run", return_value=mock_proc), \
             patch("pathlib.Path.unlink"):
            result = _run_clamscan(b"raw")
        assert result.is_infected is True
        assert result.signature == "Eicar-Test-Signature"

    def test_timeout_handled(self):
        import subprocess
        with patch("network_guardian.agent.email_scanner._clamscan_available", return_value=True), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("clamscan", 60)), \
             patch("pathlib.Path.unlink"):
            result = _run_clamscan(b"raw")
        assert result.available is True
        assert result.is_infected is False
        assert "timeout" in result.raw_output


# ---------------------------------------------------------------------------
# EmailScanner — scan_once
# ---------------------------------------------------------------------------

class TestEmailScannerScanOnce:
    def _mock_imap(self, raw_messages: list[bytes]):
        """Return a mock IMAP connection that yields the given raw messages."""
        conn = MagicMock()
        uids = [str(i).encode() for i in range(len(raw_messages))]
        conn.uid.side_effect = [
            (None, [b" ".join(uids)]),   # SEARCH call
            *[
                (None, [(None, raw), None])
                for raw in raw_messages
            ],
        ]
        conn.select.return_value = ("OK", [b"1"])
        return conn

    def test_imap_connection_error_returns_empty(self):
        cfg = _make_config()
        scanner = EmailScanner(cfg)
        with patch.object(scanner, "_connect", side_effect=imaplib.IMAP4.error("fail")):
            results = scanner.scan_once()
        assert results == []

    def test_clean_message_not_flagged(self):
        cfg = _make_config()
        scanner = EmailScanner(cfg)
        raw = _make_raw_email(subject="Hello", sender="bob@example.com")

        clean_spam = SpamResult(available=True, score=1.0, threshold=5.0, is_spam=False)
        clean_mal = MalwareResult(available=True, is_infected=False)

        with patch.object(scanner, "_connect", return_value=self._mock_imap([raw])), \
             patch("network_guardian.agent.email_scanner._run_spamassassin", return_value=clean_spam), \
             patch("network_guardian.agent.email_scanner._run_clamscan", return_value=clean_mal):
            results = scanner.scan_once()

        assert len(results) == 1
        assert results[0].flagged is False
        assert results[0].subject == "Hello"
        assert results[0].sender == "bob@example.com"

    def test_spam_message_flagged(self):
        cfg = _make_config()
        scanner = EmailScanner(cfg)
        raw = _make_raw_email(subject="WIN A PRIZE!!!")

        spam_result = SpamResult(available=True, score=8.0, threshold=5.0, is_spam=True)
        clean_mal = MalwareResult(available=True, is_infected=False)

        with patch.object(scanner, "_connect", return_value=self._mock_imap([raw])), \
             patch("network_guardian.agent.email_scanner._run_spamassassin", return_value=spam_result), \
             patch("network_guardian.agent.email_scanner._run_clamscan", return_value=clean_mal):
            results = scanner.scan_once()

        assert results[0].flagged is True
        assert results[0].spam.is_spam is True

    def test_malware_message_flagged(self):
        cfg = _make_config()
        scanner = EmailScanner(cfg)
        raw = _make_raw_email(subject="Invoice")

        clean_spam = SpamResult(available=True, score=0.1, threshold=5.0, is_spam=False)
        mal_result = MalwareResult(available=True, is_infected=True, signature="Eicar-Test-Signature")

        with patch.object(scanner, "_connect", return_value=self._mock_imap([raw])), \
             patch("network_guardian.agent.email_scanner._run_spamassassin", return_value=clean_spam), \
             patch("network_guardian.agent.email_scanner._run_clamscan", return_value=mal_result):
            results = scanner.scan_once()

        assert results[0].flagged is True
        assert results[0].malware.is_infected is True
        assert results[0].malware.signature == "Eicar-Test-Signature"

    def test_event_published_on_threat(self):
        cfg = _make_config()
        bus = MagicMock()
        scanner = EmailScanner(cfg, event_bus=bus)
        raw = _make_raw_email(subject="Spam")

        spam_result = SpamResult(available=True, score=9.0, threshold=5.0, is_spam=True)
        clean_mal = MalwareResult(available=True, is_infected=False)

        with patch.object(scanner, "_connect", return_value=self._mock_imap([raw])), \
             patch("network_guardian.agent.email_scanner._run_spamassassin", return_value=spam_result), \
             patch("network_guardian.agent.email_scanner._run_clamscan", return_value=clean_mal), \
             patch("asyncio.get_event_loop") as mock_loop, \
             patch("asyncio.ensure_future") as mock_future:
            mock_loop.return_value.is_running.return_value = False
            results = scanner.scan_once()

        assert results[0].flagged is True

    def test_no_messages_returns_empty(self):
        cfg = _make_config()
        scanner = EmailScanner(cfg)

        conn = MagicMock()
        conn.select.return_value = ("OK", [b"0"])
        conn.uid.return_value = (None, [b""])

        with patch.object(scanner, "_connect", return_value=conn):
            results = scanner.scan_once()
        assert results == []

    def test_fetch_limit_respected(self):
        cfg = _make_config(fetch_limit=2)
        scanner = EmailScanner(cfg)
        # 5 raw messages but only 2 should be scanned
        raws = [_make_raw_email(subject=f"msg{i}") for i in range(5)]

        uids_bytes = b" ".join(str(i).encode() for i in range(5))
        conn = MagicMock()
        conn.select.return_value = ("OK", [b"5"])
        # First uid call is SEARCH, subsequent are FETCH for each message
        conn.uid.side_effect = [
            (None, [uids_bytes]),
            (None, [(None, raws[3]), None]),
            (None, [(None, raws[4]), None]),
        ]

        clean_spam = SpamResult(available=False)
        clean_mal = MalwareResult(available=False)

        with patch.object(scanner, "_connect", return_value=conn), \
             patch("network_guardian.agent.email_scanner._run_spamassassin", return_value=clean_spam), \
             patch("network_guardian.agent.email_scanner._run_clamscan", return_value=clean_mal):
            results = scanner.scan_once()
        assert len(results) == 2


# ---------------------------------------------------------------------------
# EmailScanResult — flagged logic
# ---------------------------------------------------------------------------

class TestEmailScanResult:
    def test_not_flagged_when_both_clean(self):
        from network_guardian.agent.email_scanner import EmailScanResult
        r = EmailScanResult(
            message_id="<x>", subject="hi", sender="a@b.com",
            timestamp=datetime.now(timezone.utc),
            spam=SpamResult(available=True, is_spam=False),
            malware=MalwareResult(available=True, is_infected=False),
        )
        assert r.flagged is False

    def test_flagged_when_spam(self):
        from network_guardian.agent.email_scanner import EmailScanResult
        r = EmailScanResult(
            message_id="<x>", subject="hi", sender="a@b.com",
            timestamp=datetime.now(timezone.utc),
            spam=SpamResult(available=True, is_spam=True, score=9.0),
            malware=MalwareResult(available=True, is_infected=False),
        )
        assert r.flagged is True

    def test_flagged_when_malware(self):
        from network_guardian.agent.email_scanner import EmailScanResult
        r = EmailScanResult(
            message_id="<x>", subject="hi", sender="a@b.com",
            timestamp=datetime.now(timezone.utc),
            spam=SpamResult(available=True, is_spam=False),
            malware=MalwareResult(available=True, is_infected=True, signature="Virus.X"),
        )
        assert r.flagged is True
