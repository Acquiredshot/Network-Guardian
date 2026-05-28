# Network Guardian

> **Autonomous network security platform** — IDS/IPS, 24/7 AI anomaly detection, malware process scanning, real-time ransomware monitoring, fleet agents with covert comms, automatic PDF/Markdown incident reporting, remote control via phone, and a live web dashboard. Pure Python 3.11, zero heavy ML deps.

**Live demo:** https://network-guardian-cc8900c70290.herokuapp.com (credentials provided separately)

---

## Capabilities

| Capability | Summary |
|---|---|
| **IDS** | 15 signature rules, payload analysis, brute-force & multi-stage attack correlation, alert suppression |
| **IPS** | IP block/allowlist, rate limiting, quarantine zones, auto-respond to IDS alerts |
| **IP Cloaking** | MAC masking, IP obfuscation, source rotation, decoy generation, proxy chains, named identities |
| **Fleet Agents** | `ng-probe` (periodic scanner) and `ng-sentinel` (persistent stay-behind bot) phone home over Tor/proxy |
| **Covert Comms** | Tor/SOCKS5/HTTP proxy, timing jitter, UA rotation, decoy requests, body padding — base IP never exposed |
| **24/7 AI Monitor** | Background asyncio loop — rolling time-series, spike detection, 4-tier anomaly thresholds, live AI event stream |
| **Malware ReAct Agent** | Autonomous process scanner running Observe → Reason → Act → Learn. Classifies each finding by severity (critical/high/medium), computes a 0–100 threat score, and generates a branded PDF report on every threat detection |
| **Ransomware ReAct Agent** | Real-time file-system watcher that triggers a full ReAct reasoning cycle on every alert (ransomware extension or burst activity), with optional auto-quarantine and per-alert PDF reports |
| **PDF Threat Reports** | ReportLab-generated, branded PDF reports covering the full ReAct chain, threat inventory, actions taken, and recommendations — auto-saved and downloadable from the dashboard |
| **Threat Reports** | Automatic `ThreatReport` generated on every threat with full CVSS-style scoring, explanations, and recommended response steps |
| **Incident Reports** | Auto-generated Markdown incident reports saved to `incident_reports/` on every detection event |
| **ML / AI Engine** | Isolation Forest, One-Class SVM, ARIMA/Holt-Winters forecasting, ROS-style AI node graph, NLP parsing |
| **Remote Control** | WhatsApp, SMS (Twilio), Telegram, Discord, Slack — per-user permissions, rate limiting, webhook verification |
| **Dashboard** | Zero-dep async HTTP dashboard with Fleet Map canvas, live AI Engine charts, threat feed, Threat Detection page, Reports, and Incidents pages |
| **Plugin System** | Extensible registry for custom sensors, models, and dashboard components |
| **Password Manager** | CLI credential vault (`password_vault.json`) + team user management — PBKDF2-HMAC-SHA256, atomic persistence, integrated with `TeamStore` |
| **Email Protection** | IMAP email scanner — SpamAssassin spam/phishing scoring + ClamAV malware detection, async polling loop, event bus integration |
| **Email ReAct Agent** | Autonomous Observe → Reason → Act → Learn email threat agent — per-cycle risk scoring, PDF reports, history persistence, dashboard event bus integration |

---

## Dashboard Pages

| Page | Route | Description |
|---|---|---|
| **Dashboard** | `/` | Live Fleet Map, KPI bar, event feed |
| **IDS** | `/ids` | Alert log, rule hits, correlation events |
| **IPS** | `/ips` | Block list, rate-limit table, quarantine zones |
| **WiFi** | `/wifi` | Connected networks, rogue AP alerts, SSID history |
| **Cloaking** | `/cloaking` | Active identity, MAC/IP rotation status |
| **Explorer** | `/explorer` | Network topology discovery |
| **Auditor** | `/auditor` | Compliance audit findings |
| **AI Engine** | `/ai` | 24/7 rolling time-series charts, anomaly count, live AI event stream |
| **Fleet** | `/fleet` | All registered agents, per-agent drill-down, threat summary |
| **Reports** | `/reports` | Filterable threat assessment cards with expandable detail |
| **Incidents** | `/incidents` | Inline rendered Markdown incident reports with `.md` download |
| **Threat Detection** | `/security` | Malware ReAct scanner + Ransomware ReAct monitor with live results and PDF download |

---

## Quick Start

```bash
pip install -e ".[dev]"
network-guardian                                   # interactive CLI
python _start_dashboard.py                         # web dashboard at http://127.0.0.1:8080
python password_manager.py                         # credential vault + team user management CLI
python -m network_guardian.agent.email_scanner     # one-shot email scan CLI
python -m network_guardian.agent.email_react_agent # autonomous email ReAct agent CLI
```

---

## Email Protection

Scans incoming (and outgoing) email for spam, phishing, and malware. Lives at `network_guardian/agent/email_scanner.py`.

### Dependencies

| Tool | Purpose | Install |
|---|---|---|
| `spamc` (SpamAssassin) | Spam / phishing scoring | `brew install spamassassin` or `apt install spamassassin` |
| `clamscan` (ClamAV) | Malware / virus detection | `brew install clamav` or `apt install clamav` |
| Python `imaplib` / `email` | IMAP connection & message parsing | Standard library — no install needed |

If either CLI tool is absent the corresponding check is skipped and flagged in the result — the scanner still runs with whatever tools are available.

### Quick start

```bash
python -m network_guardian.agent.email_scanner
# prompts for IMAP host, email address, password, and mailbox
```

### Programmatic usage

```python
import asyncio
from network_guardian.agent.email_scanner import EmailScanner, EmailScanConfig

config = EmailScanConfig(
    imap_host="imap.gmail.com",
    imap_user="you@gmail.com",
    imap_password="app-password",   # use an app-specific password, not your account password
    spam_threshold=5.0,             # SpamAssassin score above which a message is flagged
    fetch_limit=50,                 # max unseen messages per run
)

scanner = EmailScanner(config)

# Single scan (synchronous)
results = scanner.scan_once()
for r in results:
    if r.flagged:
        print(r.sender, r.subject, r.spam.score, r.malware.signature)

# Continuous async loop — scans every 5 minutes
asyncio.run(scanner.run(interval_seconds=300))
```

### Result structure

```
EmailScanResult
  .message_id      — Message-ID header (or IMAP UID)
  .subject         — decoded Subject header
  .sender          — From header
  .timestamp       — parsed Date header (timezone-aware)
  .flagged         — True if spam OR malware detected
  .spam
    .available     — False if spamc not installed
    .score         — SpamAssassin score (float)
    .threshold     — configured threshold
    .is_spam       — True if score ≥ threshold
  .malware
    .available     — False if clamscan not installed
    .is_infected   — True if a signature was found
    .signature     — ClamAV signature name (e.g. "Eicar-Test-Signature")
```

### Event bus

Pass an `EventBus` instance to `EmailScanner(config, event_bus=bus)` and every flagged message will emit a `email.threat_detected` event into the live dashboard feed.

---

## Email ReAct Agent

Wraps the Email Protection scanner inside a full autonomous **Observe → Reason → Act → Learn** cycle, matching the `MalwareReActAgent` and `RansomwareReActAgent` patterns.

Lives at `network_guardian/agent/email_react_agent.py`.

### ReAct cycle

| Phase | What happens |
|---|---|
| **OBSERVE** | Connects to IMAP, fetches unseen messages via `EmailScanner` |
| **REASON** | Classifies each flagged message — malware → `critical`; spam scored by SpamAssassin band (`medium` / `high` / `critical`); computes 0–100 cumulative threat score |
| **ACT** | Logs all threats, builds recommendations, publishes `email.react.threat_detected` to the event bus, generates branded PDF report on high/critical cycles |
| **LEARN** | Appends to `~/.network_guardian/email_react/scan_history.json` (capped at 500 cycles); computes rising/stable trend from the last 10 cycles |

### Usage

```bash
# Interactive CLI (one-shot or loop)
python -m network_guardian.agent.email_react_agent
```

```python
import asyncio
from network_guardian.agent.email_react_agent import EmailReActAgent, EmailReActConfig

cfg = EmailReActConfig(
    imap_host="imap.gmail.com",
    imap_user="you@gmail.com",
    imap_password="app-password",
    spam_threshold=5.0,
    interval_secs=300,        # scan every 5 minutes
    generate_pdf="on_threat", # "on_threat" | "always" | "never"
)
agent = EmailReActAgent(cfg)

# One-shot cycle
report = asyncio.run(agent.run_cycle())
print(report.risk_level, report.threat_score, report.messages_flagged)

# Autonomous loop
asyncio.run(agent.run())

# Background task on existing event loop (same interface as other ReAct agents)
agent.start()
# ... later ...
agent.stop()
```

### Output

- **PDF reports** — `~/.network_guardian/email_react/pdf_reports/` and `./pdf_reports/`
- **Scan history** — `~/.network_guardian/email_react/scan_history.json`
- **Event bus topic** — `email.react.threat_detected`

---

## Password Manager

A unified CLI for managing both the credential vault and team operator accounts.

```bash
python password_manager.py
```

### Credential Vault (options 1–4)

Stores credentials for external services in `password_vault.json` alongside the project. Passwords are never stored in plaintext — each entry holds a PBKDF2-HMAC-SHA256 hash, a random salt, and (for generated passwords only) the original plaintext so it can be shown once.

| Option | Action |
|---|---|
| 1 | Add a vault entry with a user-supplied password |
| 2 | Verify a stored password interactively |
| 3 | Generate a cryptographically random password (`secrets.token_urlsafe(16)`) and store it |
| 4 | List all vault labels (plaintext shown for generated entries, `[REDACTED]` otherwise) |

### Team User Accounts (options 5–8)

Directly manages `~/.network_guardian/wolfpak_team.json` via the same `TeamStore` used by the live dashboard — any changes are immediately reflected without a server restart.

| Option | Action |
|---|---|
| 5 | Add a new operator or admin account |
| 6 | Change an existing user's password (complexity rules enforced) |
| 7 | List all users with role, active status, and days until password expiry |
| 8 | Remove a user (requires `yes` confirmation) |

### Hashing

Both the vault and team accounts use **PBKDF2-HMAC-SHA256 (260,000 iterations)** with per-entry random salts and constant-time comparison — the same algorithm as `network_guardian.interface._security`. No external crypto dependencies required.

---

## Threat Detection (Malware + Ransomware)

### Malware ReAct Agent

Scans all running processes and runs a full autonomous ReAct cycle:

```
OBSERVE  → scan_processes() via psutil; collect host metadata
REASON   → classify each finding by severity; compute 0–100 threat score
ACT      → log threats; optionally SIGTERM suspicious PIDs; publish event; generate PDF
LEARN    → persist threat history to ~/.network_guardian/malware_react/
```

**Triggered from the dashboard** — click **Run ReAct Scan** on the Threat Detection page. Results render inline with severity badges, risk level, and a one-click PDF download.

Can also be run programmatically:

```python
from network_guardian.agent.malware_react_agent import MalwareReActAgent
import asyncio

agent = MalwareReActAgent(auto_kill=False, generate_pdf="on_threat")
report = asyncio.run(agent.run_cycle())
print(report.risk_level, report.threat_score, report.pdf_path)
```

### Ransomware ReAct Agent

Watches a directory tree in real time (watchdog) and triggers a ReAct cycle on every alert:

```
OBSERVE  → capture file-system event (ransomware extension or burst of N+ writes in T seconds)
REASON   → classify severity; correlate with recent alert history; escalate if pattern repeats
ACT      → optionally quarantine file; publish event; generate PDF report
LEARN    → persist alert history to ~/.network_guardian/ransomware_react/
```

**Triggered from the dashboard** — click **Start ReAct Monitor** on the Threat Detection page. The button becomes **Stop ReAct Monitor** while active. Alerts render live and a PDF download link appears after the first detection.

```python
from network_guardian.agent.ransomware_react_agent import RansomwareReActAgent

agent = RansomwareReActAgent(
    auto_quarantine=False,
    generate_pdf="on_threat",
    watch_folder="/home/user/Documents",
)
agent.start()   # watchdog + ReAct consumer run in background threads/tasks
```

### PDF Report Output

Every ReAct cycle that detects a threat produces a branded A4 PDF containing:

- **Header banner** with report ID, date, and type
- **KPI strip** — Risk Level · Threat Score · Threats Found · Actions Taken
- **Assessment Overview** — agent label, platform, scan metadata
- **ReAct Chain** — colour-coded Observe/Reason/Act/Learn steps with timestamps
- **Threat Inventory** — severity, category, detail, action, resolution status
- **Automated Actions** — action name, description, success/fail
- **Recommendations** — prioritised numbered list

PDFs are saved to:
- `~/.network_guardian/pdf_reports/` (persistent storage)
- `./pdf_reports/` (project directory mirror)

Download directly from the dashboard via the **Download ReAct PDF Report** button that appears after each scan or alert.

Detection history is also persisted as JSON:
- Malware: `~/.network_guardian/malware_react/threat_history.json`
- Ransomware: `~/.network_guardian/ransomware_react/alert_history.json`

---

## Fleet Agents

```bash
# Probe — periodic scanner that phones home every ~60s
python -m network_guardian.agent.probe \
  --base https://YOUR-DASHBOARD-URL \
  --key YOUR_FLEET_KEY \
  --tor --stealth

# Sentinel — persistent stay-behind bot
python -m network_guardian.agent.sentinel \
  --base https://YOUR-DASHBOARD-URL \
  --key YOUR_FLEET_KEY \
  --tor --stealth
```

Covert flags: `--tor`, `--proxy socks5://...`, `--stealth` (30–300s jitter + decoys). The dashboard base URL is never exposed on the wire.

### Standalone probe (zero-dep, team distribution)

To give a team member a probe with no setup required:

```bash
python3 ng_probe_standalone.py   # prompts for Wolfpak credentials on first run
python3 ng_probe_standalone.py --install  # run as background service (auto-starts on reboot)
```

`ng_probe_standalone.py` requires **only Python 3.11+** — no pip, no repo clone. Base URL and fleet key are pre-baked in the file. Create the team member's account on the dashboard first (Team Management → Add Member).

Each agent runs a **ReAct loop** (Observe → Reason → Act → Learn) and automatically generates:
- A `ThreatReport` (structured JSON with scores, explanations, response steps) on every threat or every 10 clean cycles
- A Markdown incident report matching the `INCIDENT_REPORT_2026-04-13.md` format, saved locally and transmitted to the dashboard fleet store

---

## 24/7 AI Monitoring Loop

The dashboard runs a background `asyncio` task (`_ai_monitor_loop`) that ticks every **10 seconds** for the lifetime of the server:

- Ingests live diagnostics from every active fleet agent
- Builds **rolling 100-point time-series** for: threat score, active connections, external connections, network drift %, process drift %, active processes, listening ports
- Detects anomalies via 4 thresholds: critical score (≥70), elevated score (≥40), network baseline drift (>30%), process drift (>40%)
- Detects **metric spikes** (value > 2.5× recent rolling average)
- Emits typed `ai.*` events into the live event feed
- Populates `/api/ai/metrics` which the AI Engine page polls every 4 seconds

---

## Threat Reports & Incident Reports

Every threat detection generates up to three documents:

1. **PDF Threat Report** — branded A4 PDF produced by the ReAct agents via ReportLab:
   - Full Observe → Reason → Act → Learn chain with colour-coded steps
   - Threat inventory with severity, CVSS-style scores, and actions taken
   - Recommendations and environment snapshot
   - Saved to `~/.network_guardian/pdf_reports/` and `./pdf_reports/`
   - Downloadable from the **Threat Detection** dashboard page (`/security`)

2. **Threat Report** (`ThreatReport` dataclass) — structured JSON with:
   - Per-threat severity, CVSS-style scoring, and plain-English explanations
   - Recommended immediate and long-term response steps
   - Observation snapshot (connections, processes, ports, baseline drift)
   - Stored in fleet per-agent, accessible via `/reports`

3. **Markdown Incident Report** — prose narrative saved to:
   - `~/.ng_agent/incident_reports/` (on the agent machine)
   - `./incident_reports/` (in the project directory)
   - Available for download from the `/incidents` dashboard page

---

## Remote Control (WhatsApp / SMS / Telegram / Discord / Slack)

```bash
export TWILIO_ACCOUNT_SID=ACxxxx https://network-guardian-cc8900c70290.herokuapp.com/fleet TWILIO_AUTH_TOKEN=your_token  ALLOWED_NUMBERS=+1YOURPHONE
python whatsapp_server.py   # expose with: ngrok http 8765
```

Send `ping` → `pong`. Permissions: READ / EXECUTE / ADMIN.  
Key commands: `status`, `ids scan <text>`, `ips block <ip>`, `audit <target>`, `explore <subnet>`, `train anomaly`.

---

## Security Hardening (v19)

| Hardening | Detail |
|---|---|
| **Secure session cookie** | `ng_session` cookie gets `; Secure` flag automatically when served over HTTPS (`X-Forwarded-Proto: https`). Active on Heroku by default. |
| **Admin-only fleet key API** | `GET /api/fleet/key` returns HTTP 403 to any non-admin account. Operators cannot extract the raw HMAC fleet key. |
| **Password complexity** | Passwords require 8+ chars, one uppercase, one digit, and one special character. Enforced on set and change. |
| **Cache-Control on Threat Detection** | `/security` page is served with `Cache-Control: no-store, no-cache, must-revalidate` so browsers never serve a stale nonce'd page after a server restart. |
| **Unauthenticated API redirect** | All fetch calls on the Threat Detection page check the HTTP status code. A `401` response automatically redirects the browser to `/login` rather than silently failing. |

---

## Heroku Deployment

```bash
heroku create network-guardian
heroku config:set FLEET_KEY=$(python3 -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
git push heroku main
```

The `FLEET_KEY` config var persists across dyno restarts. Agents connect with `--key $FLEET_KEY`.

---

## Session Management

The dashboard uses a nonce-based CSP policy (`script-src 'nonce-...'`). The nonce is generated **once at startup** and embedded in every session token. This means:

- **Restarting the server invalidates all open browser sessions.** After a restart, navigate to `http://127.0.0.1:8080/login` and log in again — any cached page will redirect automatically.
- The Threat Detection page (`/security`) is served with `Cache-Control: no-store` to prevent browsers from caching the old nonce.

---

## Patch Notes

### v20 — May 2026 (Windows Compatibility + Dependency Hardening)

**Bug fixes:**

| Fix | Detail |
|---|---|
| **Windows signal handler crash** | `loop.add_signal_handler()` raises `NotImplementedError` on Windows asyncio. `_start_dashboard.py` now falls back to `signal.signal()` via try/except so the server starts cleanly on all platforms. |
| **Dynamic startup URL** | `_start_dashboard.py` now prints the correct port in the startup banner (e.g. `http://127.0.0.1:8081`) regardless of the `PORT` environment variable. |
| **Dashboard rich UI restored** | All 12 dashboard pages (`/`, `/ids`, `/ips`, `/wifi`, `/cloaking`, `/explorer`, `/auditor`, `/ai`, `/fleet`, `/reports`, `/incidents`, `/security`) restored to full rich HTML templates with live charts, KPI bars, and interactive controls. |
| **Missing runtime dependencies** | `psutil` (malware scanner), `watchdog` (ransomware monitor), and `reportlab` (PDF reports) were not installed in the virtual environment. All three are now pinned in `requirements.txt` and verified importable. |

**Verified after patch:**

- `pytest tests/ -v` → **388 / 388 passed**, 0 failures
- Live endpoint scan → **40 / 40 HTTP 200** (all pages + all API routes, authenticated)

---

## Testing

```bash
pytest tests/ -v   # 388 tests, all passing
```

---

## Requirements

- Python 3.11+, zero external ML deps (core platform)
- Root/admin for network scanning (ping, Nmap)
- `reportlab` — PDF report generation (installed automatically via `pip install -e .`)
- `psutil` — malware process scanning
- `watchdog` — real-time ransomware filesystem monitoring
- Optional: `pyyaml`, `twilio`, `cmdop`, `cmdop-bot`, `openclaw`

---

## Secret Hygiene

Never commit real credentials. Use env vars or platform secrets. Run `grep -RInE "(token|secret|password|fleet_key)" .` before every push. Keep the repo **private**.

---

## License

This project is proprietary and closed-source.

- Copyright © 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
- Legal owner: Wolf-Pak Innovations LLC (Michigan, USA).
- No permission is granted to use, copy, modify, distribute, sublicense, sell, or create derivatives without prior written authorization.
- Commercial use requires a separate paid commercial license agreement.
- See `LICENSE` and `COPYRIGHT` for full terms.

## Legal and Commercial Ops

- Federal filing checklist packet: `FEDERAL_COPYRIGHT_REGISTRATION_PACKET.txt`
- Commercial license agreement template: `COMMERCIAL_EULA.txt`
- Inbound commercial request intake form: `LICENSE_REQUEST_INTAKE_FORM.txt`
- Internal pricing and tier matrix: `PRICING_TIER_MATRIX.txt`
