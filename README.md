# Network Guardian

> **Autonomous network security platform** — IDS/IPS, 24/7 AI anomaly detection, LangGraph + DeepSeek-R1 triage, a J.A.R.V.I.S. conversational terminal shell, malware/ransomware ReAct agents, fleet agents with covert comms, automatic PDF/Markdown incident reporting, remote control via chat, a live web dashboard, and a SaaS multi-tenant control plane. Pure Python 3.13, zero heavy ML deps.

**Live demo:** Hosted cloud demo (credentials provided separately)
**Current state:** v54, production-hardened, version 1.0.0. See [CHANGELOG.md](CHANGELOG.md) and [PATCHES.md](PATCHES.md) for full release history.

**Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.**

---

## Core Subsystems

| Layer | What it does |
|---|---|
| **IDS / IPS** | 15 signature rules, payload analysis, brute-force & multi-stage correlation, IP block/allow, rate limiting, quarantine zones |
| **Smart Firewall Agent** | Autonomous injection blocker — 36 rules across 10 injection types (SQLi, XSS, CMDi, LDAP, XXE, SSTI, path traversal, header/NoSQL/GraphQL), escalating IP blocks, event-bus driven |
| **IP Cloaking / Covert Comms** | MAC masking, IP obfuscation, Tor/SOCKS5/HTTP proxy, timing jitter, UA rotation, decoy traffic |
| **Fleet Agents** | `ng-probe` (periodic) and `ng-sentinel` (persistent) phone home over Tor/proxy; zero-dep standalone probe available |
| **24/7 AI Monitor** | Rolling time-series, spike detection, 4-tier anomaly thresholds, live AI event stream |
| **Per-Device UEBA + Lateral Movement** | Personal Isolation Forest baseline per IP; fan-out/lateral-movement alerts at ≥3σ or 20+ destinations |
| **Malware / Ransomware ReAct Agents** | Observe → Reason → Act → Learn cycles, 0–100 threat scoring, auto-quarantine option, branded PDF report per detection |
| **Email Protection + ReAct Agent** | IMAP scanner (SpamAssassin + ClamAV + AI classification), full ReAct cycle, PDF reports |
| **LangGraph + DeepSeek-R1** | Chain-of-thought triage (`ingest → reason → plan → summarize`); activates when `DEEPSEEK_API_KEY` is set, keyword fallback otherwise |
| **J.A.R.V.I.S. Terminal Shell** | Conversational REPL, live telemetry, voice I/O (SAPI 5 + wake-word), read-only Probe Commander for fleet awareness |
| **MCP/API Protocol Parser** | Semantic threat detection for JSON-RPC 2.0, MCP, GraphQL, multi-agent payloads — prompt injection, tool abuse, schema exfiltration |
| **Remote Control** | Telegram, Discord, Slack — per-user permissions, rate limiting, webhook verification |
| **Dashboard** | Zero-dep async HTTP server — Fleet Map, AI charts, threat feed, Reports, Incidents (see table below) |
| **SaaS Control Plane** | Multi-tenant auth, orgs, API keys, fleet ingest API, billing checkout/portal/webhook (SQLite + PostgreSQL) |
| **Desktop App** | Native PyQt5 firewall console sharing the same engine as the web dashboard |
| **Password Manager** | CLI credential vault + team account management — PBKDF2-HMAC-SHA256 |
| **Plugin System** | Extensible registry for custom sensors, models, and dashboard components |

## Dashboard Pages

| Page | Route | Description |
|---|---|---|
| Dashboard | `/` | Live Fleet Map, KPI bar, event feed |
| IDS / IPS | `/ids`, `/ips` | Alert log, rule hits, block list, quarantine zones |
| WiFi | `/wifi` | Connected networks, rogue AP alerts |
| Cloaking | `/cloaking` | Active identity, MAC/IP rotation status |
| Explorer / Auditor | `/explorer`, `/auditor` | Topology discovery, compliance findings |
| AI Engine | `/ai` | Rolling anomaly charts, live AI event stream |
| Fleet | `/fleet` | Registered agents, per-agent drill-down |
| Reports / Incidents | `/reports`, `/incidents` | Threat assessment cards, Markdown incident reports |
| Threat Detection | `/security` | Malware/Ransomware ReAct scanners with PDF download |

---

## Quick Start

```bash
pip install -e ".[dev]"

# Dashboard only (default port 8080; set PORT env var to override)
python _start_dashboard.py

# SaaS control plane (requires JWT_SECRET; Stripe vars optional for mock billing)
JWT_SECRET=your-secret STRIPE_WEBHOOK_SECRET=whsec_xxx python _start_dashboard.py

# J.A.R.V.I.S. terminal shell
python -m network_guardian.jarvis.jarvis_core
DEEPSEEK_API_KEY=sk-<key> python -m network_guardian.jarvis.jarvis_core   # with DeepSeek-R1 triage

# Fleet probe (env vars keep credentials out of `ps`/Task Manager)
export NG_BASE=https://YOUR-DASHBOARD-URL
export NG_KEY=YOUR_FLEET_KEY
python -m network_guardian.agent.probe --tor --stealth

# Desktop app
python -m network_guardian --desktop
```

More detail: [LOCAL_STARTUP.md](LOCAL_STARTUP.md) · [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) · [CROSS_PLATFORM_SETUP.md](CROSS_PLATFORM_SETUP.md) · [README_TEAM_SETUP.md](README_TEAM_SETUP.md) · [DATA_COLLECTION_GUIDE.md](DATA_COLLECTION_GUIDE.md)

---

## Testing

```bash
pytest tests/ -v
```

## Requirements

- Python 3.11+, zero external ML deps (core platform)
- Root/admin for network scanning (ping, Nmap)
- `reportlab` (PDF reports), `psutil` (malware scan), `watchdog` (ransomware monitor) — all installed via `pip install -e .`
- Optional: `pyyaml`, `langgraph` + `langchain-openai` + `langchain-core` (DeepSeek-R1 triage), `PyQt5` (desktop app)

---

## Secret Hygiene

Never commit real credentials. Use env vars or platform secrets. Run `grep -RInE "(token|secret|password|fleet_key)" .` before every push. Keep the repo **private**.

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
