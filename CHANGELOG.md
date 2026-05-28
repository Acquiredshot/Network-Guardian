# Changelog — Network Guardian

All notable changes to this project are documented here.

---

## [v26] — 2026-05-28

### Fixed — Windows Compatibility

#### `network_guardian/agent/react_agent.py`
- `_get_arp_table()` — added Windows branch to parse `arp -a` output (column-format with dash-separated MACs `00-50-56-c0-00-08`); macOS/Linux regex-based parser retained for those platforms.
- `_get_gateway()` — added Windows branch using `route print 0.0.0.0`; parses the Active Routes table (`0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>`).
- `_get_dns_servers()` — added Windows branch using `ipconfig /all`; parses `DNS Servers` lines, extracts dot-notation IPs.

#### `network_guardian/interface/desktop.py`
- Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()`. `get_event_loop()` was deprecated in Python 3.10 and removed in 3.12; this fix is required for all Python 3.12+ environments on any platform.

---

## [v25] — 2026-05-28

### Added

#### Safe Web Browsing Agent (`network_guardian/agent/web_browsing_agent.py`)
- New autonomous URL safety evaluation agent following the **Observe → Reason → Act → Learn** cycle.
- **`UrlCategory` enum**: `TRUSTED` / `BLOCKED` / `SAFE` / `SUSPICIOUS` / `MALICIOUS` / `ERROR` / `SKIPPED`
- **`ThreatSignal`** and **`UrlVerdict`** dataclasses for structured per-URL results.
- **17 content threat signals** across six categories:
  - Phishing: account verification, billing update, account suspension, CTA click
  - Malware: keywords, drive-by download, `eval(unescape())`, `eval(atob())`, `document.write(unescape())`
  - Hidden iframes (display:none / visibility:hidden)
  - Cryptominer injection: CoinHive, CryptoNight, Worker blob patterns
  - Exploit kit language and named EK detection (BlackHole, Angler, Nuclear, etc.)
  - Credential harvesting forms and scam/prize content
- **SSRF guard**: private, loopback, and link-local addresses are refused before any HTTP connection is attempted.
- **WAF-safe domain matching**: hostname extracted via `urllib.parse.urlparse` + wildcard subdomain support (`*.evil.com`) — no regex on user-supplied input strings.
- **HTTP fetch hardening**: `timeout=(5, 15)`, 512 KB content cap (streaming), max 5 redirects, SSL certificate verification enforced, `lxml` parser with `html.parser` fallback.
- **Persistent allowlist/blocklist**: saved to `~/.network_guardian/web_browsing/domain_lists.json`.
- **Management API**: `add_to_blocklist()`, `remove_from_blocklist()`, `add_to_allowlist()`, `remove_from_allowlist()`, `get_stats()`, `dashboard_summary()`.
- **Verdict history**: capped at 1,000 entries in memory.
- **Event bus integration**: publishes `web.url.verdict` events.
- **IPS integration**: `MALICIOUS` verdicts trigger automatic `ips.block_ip()` (1h, when `auto_block=True`).
- **Engine property**: `engine.web_browsing` lazy property wired into `Engine`; stop lifecycle logs stats summary.
- **CLI**: `check`, `block`, `allow`, `unblock`, `unallow`, `blocklist`, `allowlist`, `stats`, `history`, `help`, `quit`.
- **Dependencies**: `requests>=2.32`, `beautifulsoup4>=4.12`, `lxml>=5.0` added to `requirements.txt` and `pyproject.toml`.

---

## [v24] — 2026-05-27

### Added

#### Smart Firewall Agent — Bypass Detection, NoSQL/GraphQL Rules, Reputation Scoring, Management API

**WAF-bypass payload normalisation** (`_normalize_payload`)
- Before running any detection rule the payload is decoded into up to **7 variants**: original, URL-decoded (×1), URL-decoded (×2, double-encoding bypass), HTML entity decoded, Unicode NFKC normalised (homoglyph bypass), SQL inline-comment stripped (`UN/**/ION`), null-byte removed, and base64 decoded. Rules are tested against all variants so encoded attacks can no longer slip through.

**Two new injection categories** (10 types total, 36 rules total):
- **NoSQL Injection** — 4 rules covering MongoDB `$where`/`$ne`/`$gt` operator injection, `$where` JavaScript execution, array-operator bypass, and JSON key injection.
- **GraphQL Injection** — 3 rules covering `__schema`/`__type` introspection probes, aliased-query batch amplification attacks, and deeply nested query DoS.

**IP reputation scoring** (`reputation_score`, `_update_reputation`)
- Each detected injection accumulates a floating-point threat score per source IP (0–100). Delta is `sev_delta × confidence` where `sev_delta` is 30 (critical), 15 (high), or 5 (medium). Score persists in memory for the agent's lifetime and is accessible via `agent.reputation_score(ip)`.

**Per-agent rule management**
- `self._rules` is a per-instance shallow copy of the module-level rules list so `enable_rule`/`disable_rule` calls on one agent never affect another.
- `add_rule(InjectionRule)` — add a custom rule at runtime.
- `enable_rule(name) -> bool` — re-enable a previously disabled rule.
- `disable_rule(name) -> bool` — disable a rule without removing it.

**Confidence threshold** (`set_confidence_threshold`, `_confidence_threshold`)
- Detections whose combined confidence is below the threshold (default 0.70) are silently dropped, preventing low-signal rules from triggering blocks on ambiguous payloads.

**Rate-tracking** (`record_request`, `_request_tracker`)
- Sliding-window request counter per IP (default: 200 req/60 s). Returns `True` when the threshold is exceeded — a signal of automated scanning even without an injection match.

**Statistics & dashboard API**
- `get_stats() -> dict` — live snapshot: total scanned, total blocked, blocks last hour, top attacking IPs, injection type breakdown, false-positive count, rule metadata.
- `dashboard_summary() -> dict` — JSON-serialisable subset for the `/api/smart_firewall` dashboard endpoint.

**False-positive tracking** (`mark_false_positive`)
- `mark_false_positive(detection_id)` removes a detection from per-IP history and registers the ID in `_fp_ids` so it is excluded from stats.

**CLI extended** (`_cli_main`)
- New commands: `stats`, `rules`, `enable <rule>`, `disable <rule>`, `reputation <ip>`, `fp <detection_id>`, `threshold <float>`.

**Recommendation catalogue**
- Added remediation guidance for `NOSQL` and `GRAPHQL` injection types.

---

## [v23] — 2026-05-27

### Added

#### Smart Firewall ReAct Agent (`network_guardian/agent/smart_firewall_agent.py`)
- New autonomous injection-detection and active-blocking agent following the standard **Observe → Reason → Act → Learn** cycle:
  - **OBSERVE** — drains a queue populated by `ids.alert` event-bus subscriptions (reactive) and accepts direct `scan_payload()` calls (proactive)
  - **REASON** — classifies each injection by type, computes per-IP escalation tier, derives risk level (low / medium / high / critical) and 0–100 threat score
  - **ACT** — calls `ips.block_ip()` immediately; publishes `firewall.injection.blocked` event; generates PDF report on high/critical cycles
  - **LEARN** — persists per-IP offense history to `~/.network_guardian/smart_firewall/injection_history.json`; caps at 500 entries per IP

- **29 injection detection rules** across 8 attack categories:

  | Category | Rules | Coverage |
  |---|---|---|
  | SQL Injection | 6 | UNION SELECT, tautology, stacked queries, blind time-based, comment stripping, error-based |
  | XSS | 5 | `<script>`, event handlers, `javascript:`, SVG/IMG payloads, HTML entity obfuscation |
  | Command Injection | 4 | Pipe/semicolon/backtick/$(), file redirection, `\|\|` operator, URL-encoded shell chars |
  | LDAP Injection | 2 | Filter escape, AND/OR operator bypass |
  | XXE | 2 | SYSTEM entity declaration, parameter entity exfiltration |
  | SSTI | 4 | Jinja2/Twig `{{ }}`, FreeMarker/Spring EL `${}`, ERB `<%= %>`, Thymeleaf `#{}` |
  | Path Traversal | 4 | `../../`, URL-encoded `%2e%2e%2f`, double-encoded `%252e`, null-byte variant |
  | Header Injection | 2 | CRLF `%0d%0a`, HTTP response splitting |

- **Escalating block durations**: 1st offense → 1 hour; 2nd offense → 6 hours; 3rd+ → permanent
- `InjectionDetection` dataclass — captures detection ID, source IP, payload snippet, injection type, rule name, severity, confidence, action taken, and block duration
- `SmartFirewallReport` dataclass — full cycle summary (risk level, threat score, IPs blocked, ReAct steps, threats, actions, recommendations)
- `InjectionRule` dataclass with lazy-compiled regex patterns (`re.IGNORECASE | re.DOTALL`)
- `offense_count(ip)` — returns number of confirmed injection offenses for a source IP
- `clear_history(ip=None)` — clears offense history for one or all IPs
- `scan_payload(payload, source_ip)` — immediately analyse a single payload and (if `auto_block=True`) block the attacker
- `start()` / `stop()` / `run()` — standard async lifecycle interface matching other ReAct agents
- `generate_pdf` support — integrates with `pdf_reporter.build_report_pdf()` for PDF incident reports
- Per-injection-type recommendations catalogued in `_recommendation(InjectionType)`
- Interactive CLI: `python -m network_guardian.agent.smart_firewall_agent`

#### Engine integration (`network_guardian/core/engine.py`)
- `Engine.smart_firewall` lazy property — instantiates `SmartFirewallAgent` wired to the live `IPS` and `EventBus`
- `Engine.start()` — automatically calls `self.smart_firewall.start()` so the agent is always active
- `Engine.stop()` — calls `self._smart_firewall.stop()` for clean shutdown

#### Desktop App update (`network_guardian/interface/desktop.py`)
- **Analyze** button now routes payloads through `engine.smart_firewall.scan_payload()` first (injection detection + auto-block), then through `engine.ids.analyse_payload()` (full IDS scan)

### Changed
- `README.md` — new **Smart Firewall Agent** section (architecture, injection type table, escalation table, programmatic usage, event bus topics); Capabilities table row added; Quick Start command added

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
