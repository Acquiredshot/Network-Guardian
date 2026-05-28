# Changelog — Network Guardian

All notable changes to this project are documented here.

---

## [v22] — 2026-05-27

### Added

#### Desktop App — PyQt5 Firewall Console (`network_guardian/interface/desktop.py`)
- New `python -m network_guardian --desktop` launch flag routes to `network_guardian.interface.desktop.main()`.
- `EngineThread` — runs the full `Engine` (IDS + IPS + EventBus) on a dedicated asyncio loop inside a `QThread`; re-emits `ids.alert`, `ips.block`, and `ips.unblock` events as Qt signals so the UI never blocks.
- `SmartFirewall` (`QWidget`) — minimal desktop firewall console:
  - **Alert feed** — live IDS alert list populated as events arrive; each row shows severity, category, source IP, and description
  - **One-click block** — select any alert and click **Block source IP** to fire an immediate IPS block via `asyncio.run_coroutine_threadsafe`
  - **Auto-respond toggle** — `QCheckBox` that calls `engine.ips.set_auto_respond()` to let the IPS block automatically without user confirmation
  - **Payload analyser** — paste/type any raw payload and click **Analyze** to route it through `engine.ids.analyse_payload()`
  - **Blocked-IP list** — live list of all blocked IPs with reason and duration tag (timed / permanent)
  - **Unblock** — select a blocked IP and click **Unblock selected IP**; dispatched via `engine.ips.unblock_ip()`
- `main(config_path)` — entry point used by `__main__.py`; creates `QApplication`, instantiates `EngineThread` + `SmartFirewall`, starts the engine thread, wires `aboutToQuit` → `shutdown`, and runs the Qt event loop.
- `__main__.py` updated: `--desktop` arg added to `build_parser()`; `main()` branches to `desktop_main` when flag is set.
- `PyQt5` added to `requirements.txt` as an optional dependency.

### Changed
- `README.md` — new **Desktop App** section with install/launch instructions, feature table, and architecture diagram; Quick Start table updated with `--desktop` command; Capabilities table updated with Desktop App row.

---

## [v21] — 2026-05-27

### Added

#### Active Email Protection — IMAP write operations (`email_scanner.py`, `email_react_agent.py`)
- `EmailScanConfig` now supports three **action modes** that control what the scanner does with flagged messages:
  - `monitor` (default) — detect and report only; mailbox is never modified (`readonly=True` on IMAP SELECT)
  - `move_spam` — spam moved to Junk/Spam folder via IMAP COPY + STORE `\Deleted` + EXPUNGE; malware permanently deleted
  - `delete_all` — all flagged messages (spam and malware) permanently deleted
- `EmailScanConfig.spam_folder` — explicit override for the destination spam folder
- `EmailScanConfig.resolved_spam_folder()` — auto-detects the provider's spam folder from `imap_host` using built-in presets: Gmail → `[Gmail]/Spam`, Outlook/Hotmail → `Junk`, Yahoo → `Bulk Mail`, iCloud → `Junk`, Zoho → `Spam`, Fastmail → `Spam`; falls back to `Spam` for unknown providers
- `_SPAM_FOLDER_PRESETS` — module-level dict for provider-to-folder mapping (extensible)
- `EmailScanner._take_action()` — new private method that executes the IMAP write operation for a flagged message and returns a human-readable action string (`"none"`, `"deleted"`, `"moved_to:<folder>"`, `"error:<msg>"`)
- `EmailScanResult.action_taken` — new field recording the IMAP action performed on each message
- CLI (`python -m network_guardian.agent.email_scanner`) now prompts for protection mode, confirms before activating any write mode, and shows an `Action` column in the results table
- `EmailReActConfig.action_mode` and `.spam_folder` fields — passed through to `EmailScanConfig` so the ReAct agent can operate in active protection mode
- ReAct ACT phase now logs mode-aware recommendations (e.g. "SPAM MOVED to [Gmail]/Spam" instead of generic "mark as spam")

### Fixed
- `password_manager.py` — added `from __future__ import annotations` to fix `str | None` union syntax error on Python 3.9

### Tests
- Added `TestActiveProtection` class (7 new tests) to `tests/test_email_scanner.py`, covering: monitor mode (no IMAP writes), move_spam mode (COPY + STORE + EXPUNGE verified), delete_all mode, provider preset resolution (Gmail, custom override, unknown host), and clean-message action_taken default
- Total test count: **436 passing** (up from 429)

---

## [v20] — 2026-05-27

### Added

#### Email ReAct Agent (`network_guardian/agent/email_react_agent.py`)
- New autonomous agent that wraps `EmailScanner` inside a full **Observe → Reason → Act → Learn** cycle, matching the patterns of `MalwareReActAgent` and `RansomwareReActAgent`:
  - **OBSERVE** — connects to IMAP, fetches unseen messages, records scan counts
  - **REASON** — classifies each flagged message by severity (`critical` for malware, `medium`–`critical` for spam based on SpamAssassin score); computes a 0–100 cumulative threat score
  - **ACT** — logs all threats, generates per-cycle recommendations, publishes `email.react.threat_detected` events to the Network Guardian event bus, optionally generates a branded PDF report
  - **LEARN** — persists up to 500 cycles of scan history to `~/.network_guardian/email_react/scan_history.json`; computes rolling trend (rising / stable) from the last 10 cycles
- `EmailReActAgent.run_cycle()` — async, executes one full ReAct cycle and returns an `EmailReActReport`
- `EmailReActAgent.run()` — autonomous async loop polling at `interval_secs` (default 300s)
- `EmailReActAgent.start()` / `.stop()` — schedule/cancel the background task on the running event loop (same interface as other ReAct agents)
- PDF reports saved to `~/.network_guardian/email_react/pdf_reports/` and mirrored to `./pdf_reports/`
- Interactive CLI entry point: `python -m network_guardian.agent.email_react_agent`

#### Email Protection Scanner (`network_guardian/agent/email_scanner.py`)
- New agent module that connects to any IMAP mailbox (SSL by default) and scans unseen messages through two independent layers:
  - **SpamAssassin** (`spamc -c`) — spam/phishing scoring with configurable threshold (default 5.0). Parses the score/threshold line from `spamc` stdout; exits with `is_spam=True` when score ≥ threshold.
  - **ClamAV** (`clamscan`) — malware/virus detection. Writes each message to a temp file, scans it, and parses the signature name from the `FOUND` output line.
- Both tools are invoked as subprocesses — no additional Python packages required. If a tool is not installed on the host, its check is skipped and flagged `available=False` in the result.
- `EmailScanResult` dataclass captures: message ID, subject, sender, timestamp, `SpamResult`, `MalwareResult`, and a top-level `flagged` bool.
- `EmailScanner.scan_once()` — synchronous single-pass scan; returns a list of `EmailScanResult`.
- `EmailScanner.run(interval_seconds)` — async loop that re-scans every N seconds (default 300); safe to `await` inside the dashboard's asyncio event loop.
- Event bus integration — when a threat is detected and an `EventBus` is provided, publishes a `email.threat_detected` event with spam score, malware signature, sender, and subject.
- Interactive CLI entry point (`python -m network_guardian.agent.email_scanner`) with install hints if `spamc` or `clamscan` are missing.

#### Password Manager (`password_manager.py`)
- New unified CLI tool for credential management, integrating two distinct scopes:
  - **Credential Vault** — stores hashed credentials for external services/accounts in `password_vault.json`. Supports adding user-supplied passwords, interactive verification, and cryptographically random password generation (`secrets.token_urlsafe(16)`).
  - **Team User Management** — directly manages `~/.network_guardian/wolfpak_team.json` via `TeamStore` (the same object used by the live dashboard). Supports adding, listing, changing passwords for, and removing operator/admin accounts.
- Vault entries are persisted atomically (write-to-temp → rename) to prevent corruption on crash.
- Generated passwords store the original plaintext so they can be shown once via the list view; user-supplied passwords are always shown as `[REDACTED]`.

### Changed

#### Hashing — unified algorithm
- `password_manager.py` now uses **PBKDF2-HMAC-SHA256 (260,000 iterations)** with per-entry random salts and `hmac.compare_digest` for constant-time comparison — matching `network_guardian.interface._security` exactly.
- Removed `bcrypt` dependency (previously added in the initial draft). The codebase now has a single hashing approach across all modules. `bcrypt` removed from `requirements.txt`.

### Security

- Credential vault and team accounts never store plaintext passwords (except for auto-generated vault entries where the user has no other way to retrieve the value).
- Vault file uses the same atomic-write pattern as `TeamStore._save()` to avoid partial writes.
- Password operations use `hmac.compare_digest` throughout — no timing side-channels.

---

## [v19] — Prior

See `README.md → Security Hardening (v19)` for previous hardening notes.
