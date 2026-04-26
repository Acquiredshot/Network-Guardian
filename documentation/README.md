# Network Guardian — Documentation Index

> Autonomous network security platform by Wolf-Pak Innovations LLC  
> Copyright © 2026 Wolf-Pak Innovations LLC. All Rights Reserved.

---

## Contents

| Document | Description |
|---|---|
| [architecture.md](architecture.md) | System design, component map, data flows, event bus |
| [fleet-agents.md](fleet-agents.md) | Probe, Sentinel, ReAct loop, covert comms, threat reports |
| [ai-engine.md](ai-engine.md) | 24/7 monitor loop, anomaly detection, forecasting, SSE stream |
| [ids-ips.md](ids-ips.md) | IDS signature rules, IPS response policies, alert lifecycle |
| [dashboard.md](dashboard.md) | All pages, authentication, team management, controls |
| [api-reference.md](api-reference.md) | Every HTTP endpoint, request/response schemas |
| [deployment.md](deployment.md) | Local setup, Heroku deployment, environment variables |
| [incident-reports.md](incident-reports.md) | Threat report format, Markdown IR format, file layout |

---

## Quick Links

- **Live App:** https://network-guardian-cc8900c70290.herokuapp.com
- **Default Login:** `admin` / `<password>` *(change immediately)*
- **Fleet Key Env Var:** `FLEET_KEY`
- **Current Heroku Release:** v18

---

## Version History

| Version | Summary |
|---|
| v1–v10 | Initial build: IDS, IPS, WiFi, Cloaking, Fleet, Dashboard core |
| v11 | Heroku deployment baseline |
| v12 | Threat report system (`ThreatReport` dataclass, fleet storage) |
| v13 | Automatic Markdown incident reports on every threat event |
| v14 | `incident_reports/` folder; reports saved to project dir |
| v15 | AI Engine panels wired to fleet agent data |
| v16 | 24/7 background AI monitoring loop; probe clean-report cycle 50→10 |
| v17 | SSE `/api/ai/live` endpoint; AI Engine page uses `EventSource` |
| v18 | Security hardening: Secure session cookie on HTTPS, admin-only fleet key API, password complexity enforcement; `ng_probe_standalone.py` for zero-dep team distribution |
