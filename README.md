# Network Guardian

> **Autonomous network security platform** — IDS/IPS, 24/7 AI anomaly detection, fleet agents with covert comms, automatic incident reporting, remote control via phone, and a live web dashboard. Pure Python 3.11, zero heavy ML deps.

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
| **Threat Reports** | Automatic `ThreatReport` generated on every threat (or every 10 clean cycles) with full CVSS-style scoring, explanations, and recommended response steps |
| **Incident Reports** | Auto-generated Markdown incident reports saved to `incident_reports/` on every detection event |
| **ML / AI Engine** | Isolation Forest, One-Class SVM, ARIMA/Holt-Winters forecasting, ROS-style AI node graph, NLP parsing |
| **Remote Control** | WhatsApp, SMS (Twilio), Telegram, Discord, Slack — per-user permissions, rate limiting, webhook verification |
| **Dashboard** | Zero-dep async HTTP dashboard with Fleet Map canvas, live AI Engine charts, threat feed, Reports, and Incidents pages |
| **Plugin System** | Extensible registry for custom sensors, models, and dashboard components |

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

---

## Quick Start

```bash
pip install -e ".[dev]"
network-guardian            # interactive CLI
python _start_dashboard.py  # web dashboard at http://127.0.0.1:8080
```

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

Every threat detection generates two documents:

1. **Threat Report** (`ThreatReport` dataclass) — structured JSON with:
   - Per-threat severity, CVSS-style scoring, and plain-English explanations
   - Recommended immediate and long-term response steps
   - Observation snapshot (connections, processes, ports, baseline drift)
   - Stored in fleet per-agent, accessible via `/reports`

2. **Markdown Incident Report** — prose narrative saved to:
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

## Security Hardening (v18)

| Hardening | Detail |
|---|---|
| **Secure session cookie** | `ng_session` cookie gets `; Secure` flag automatically when served over HTTPS (`X-Forwarded-Proto: https`). Active on Heroku by default. |
| **Admin-only fleet key API** | `GET /api/fleet/key` returns HTTP 403 to any non-admin account. Operators cannot extract the raw HMAC fleet key. |
| **Password complexity** | Passwords require 8+ chars, one uppercase, one digit, and one special character. Enforced on set and change. |

---

## Heroku Deployment

```bash
heroku create network-guardian
heroku config:set FLEET_KEY=$(python3 -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
git push heroku main
```

The `FLEET_KEY` config var persists across dyno restarts. Agents connect with `--key $FLEET_KEY`.

---

## Testing

```bash
pytest tests/ -v   # 388 tests, all passing
```

---

## Requirements

- Python 3.11+, zero external ML deps
- Root/admin for network scanning (ping, Nmap)
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
