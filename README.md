# Network Guardian

> **Autonomous network security platform** — IDS/IPS, Smart Firewall, 24/7 AI anomaly detection, LangGraph + Hermes triage, J.A.R.V.I.S. conversational terminal, malware/ransomware ReAct agents, fleet probes with covert comms, automatic incident reporting, remote control via chat, live web dashboard, and a SaaS multi-tenant control plane. Pure Python 3.13, zero heavy ML deps.

**Current state:** v1.0.0, production-hardened. **Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.**

---

## What It Is

Network Guardian is a standalone network security platform you run on your own host. It watches your network and systems, detects threats, and can block attackers — all from a single machine with no external dependencies.

**It does these things out of the box:**

- **IDS/IPS** — 15 signature rules, payload analysis, brute-force & multi-stage correlation, IP block/allow, rate limiting, quarantine zones
- **Smart Firewall** — autonomous injection blocker (36 rules across SQLi, XSS, CMDi, LDAP, XXE, SSTI, path traversal, header/NoSQL/GraphQL); escalating IP blocks; event-bus driven
- **AI Anomaly Monitor** — rolling time-series, spike detection, 4-tier anomaly thresholds, live event stream
- **UEBA + Lateral Movement** — per-device Isolation Forest baseline; alerts at ≥3σ deviation or 20+ destination fan-out
- **Malware / Ransomware ReAct** — Observe → Reason → Act → Learn cycles, 0–100 threat scoring, auto-quarantine, branded PDF report per detection
- **Email Protection** — IMAP scanner (SpamAssassin + ClamAV + AI classification), full ReAct cycle, PDF reports
- **IP Cloaking / Covert Comms** — MAC masking, IP obfuscation, Tor/SOCKS5/HTTP proxy, timing jitter, UA rotation, decoy traffic
- **Fleet Probes** — `ng-probe` (periodic) and `ng-sentinel` (persistent) phone home over Tor/proxy; zero-dep standalone probe available
- **MCP/API Protocol Parser** — semantic threat detection for JSON-RPC 2.0, MCP, GraphQL, multi-agent payloads (prompt injection, tool abuse, schema exfiltration)
- **Remote Control** — Telegram, Discord, Slack; per-user permissions, rate limiting, webhook verification
- **Password Manager** — CLI credential vault + team account management (PBKDF2-HMAC-SHA256)
- **Plugin System** — extensible registry for custom sensors, models, and dashboard components

## J.A.R.V.I.S. Terminal Shell

A conversational REPL you run directly in your terminal. It aggregates live telemetry (threat level, CPU/RAM/disk, fleet devices, firewall history, probe agent statuses) and lets you talk to your network in plain English:

```bash
python -m network_guardian.jarvis.jarvis_core
```

Commands like `situation`, `triage`, `firewall scan`, `malware`, `ids alerts`, `fleet`, `probes`, `metrics` all work with natural-language aliases. Voice I/O is built in (Windows SAPI 5, with wake-word detection).

## LangGraph + Hermes Triage

When you set `HERMES_API_KEY`, J.A.R.V.I.S. uses a LangGraph state machine with Hermes for chain-of-thought triage — ingest → reason → plan → summarize. It produces a structured action plan with confidence scores and recommendations. Without the key, it falls back to a keyword scorer. No behaviour change either way.

## Dashboard

A zero-dep async HTTP dashboard runs on port 8080 (override with `PORT`). It gives you a live Fleet Map, KPI bar, event feed, and pages for IDS/IPS, WiFi, cloaking, explorer/auditor, AI engine charts, fleet agents, reports/incidents, and threat detection (malware/ransomware ReAct with PDF download).

```bash
python _start_dashboard.py
```

Front with nginx/caddy in production. SaaS mode (multi-tenant auth, orgs, API keys, billing) activates when `JWT_SECRET` is set.

## SaaS Control Plane

When `JWT_SECRET` is configured, the dashboard also serves a multi-tenant control plane on port 8081: org management, API keys, fleet ingest API, and Stripe billing checkout/portal/webhook (mock billing works without real Stripe keys). SQLite by default; PostgreSQL available.

## How It Fits With Mask and Pakshield

Network Guardian is one pillar of the **Wolf-Pak platform** — a three-product security backplane:

```
Network Guardian  ──  IDS/IPS, AI monitor, dashboard, SaaS
Pakshield         ──  Identity risk scoring + access control
Mask Network     ──  Network/asset intelligence + threat mapping
```

They share a common **Event Fabric** — a cross-app event bus with an HTTP intake endpoint and SQLite storage. Both Mask and Pakshield push their observations into Network Guardian's dashboard as structured envelopes:

```
MASK  ──▶  POST /api/event-fabric/intake  ──▶  Event Fabric  ──▶  Security Graph
PAKSHIELD ────────────────────────────────────────▶
```

- **Mask adapter** (`scripts/mask_adapter.py`) — exports Mask daemon observations (sysinfo, processes, network connections, user sessions) into the Event Fabric. Falls back to direct OS observation via psutil when the Mask daemon's IPC isn't available.
- **Pakshield adapter** (`scripts/pakshield_adapter.py`) — exports PakShield identity, risk, and access events (risk scores, findings, access decisions, device posture) from PakShield's SQLite database into the Event Fabric.
- **Security Graph** — an in-memory entity-relationship store that correlates hosts, devices, identities, processes, and network flows across all three products. Queryable via `GET /api/security-graph/summary`.
- **AI Security Orchestrator** (`scripts/orchestrator_service.py`) — wires DetectionEngine → InvestigationEngine → ResponsePlanner to the Event Fabric. Processes stored events from all three sources and publishes findings.

The real Mask and Pakshield products live in their own workspaces (`C:\Users\CodyC\MASK` and `C:\Users\CodyC\PakShield`) and are actively developed there. Network Guardian provides the ingestion and correlation layer that ties them together.

## Quick Start

```bash
pip install -e ".[dev]"

# Dashboard (port 8080; override with PORT)
python _start_dashboard.py

# SaaS mode (requires JWT_SECRET; Stripe vars optional for mock billing)
JWT_SECRET=your-secret STRIPE_WEBHOOK_SECRET=whsec_xxx python _start_dashboard.py

# J.A.R.V.I.S. terminal shell
python -m network_guardian.jarvis.jarvis_core

# With Hermes triage (set your key)
HERMES_API_KEY=sk-<key> python -m network_guardian.jarvis.jarvis_core

# Fleet probe
export NG_BASE=https://YOUR-DASHBOARD-URL
export NG_KEY=YOUR_FLEET_KEY
python -m network_guardian.agent.probe --tor --stealth
```

Push events from Mask and Pakshield into the Event Fabric:

```bash
# From the Network Guardian repo root
python scripts/mask_adapter.py --once
python scripts/pakshield_adapter.py --once
python scripts/orchestrator_service.py --once   # run detection/investigation/response
```

## Testing

```bash
pytest tests/ -v
```

## Requirements

- Python 3.11+
- Root/admin for network scanning (ping, Nmap)
- `reportlab` (PDF reports), `psutil` (malware scan), `watchdog` (ransomware monitor) — installed via `pip install -e .`
- Optional: `pyyaml`, `langgraph` + `langchain-openai` + `langchain-core` (Hermes triage), `PyQt5` (desktop app)

## Secret Hygiene

Never commit real credentials. Use env vars. Run `grep -RInE "(token|secret|password|fleet_key)" .` before every push. Keep the repo **private**.

## License

Proprietary and closed-source. Copyright © 2026 Wolf-Pak Innovations LLC. All Rights Reserved. Commercial use requires a separate paid license agreement. See `LICENSE` and `COPYRIGHT` for full terms.
