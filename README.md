# Network Guardian

> **TL;DR** — Autonomous network security platform: IDS/IPS, ML anomaly detection, fleet agents, covert comms, remote control via phone, and a live web dashboard. Pure Python, zero heavy ML deps, 388 tests passing.

## What it does

| Capability | Summary |
|---|---|
| **IDS** | 15 signature rules, payload analysis, brute-force & multi-stage attack correlation, alert suppression |
| **IPS** | IP block/allowlist, rate limiting, quarantine zones, auto-respond to IDS alerts |
| **IP Cloaking** | MAC masking, IP obfuscation, source rotation, decoy generation, proxy chains, named identities |
| **Fleet Agents** | `ng-probe` (periodic scanner) and `ng-sentinel` (persistent stay-behind bot) phone home over Tor/proxy |
| **Covert Comms** | Tor/SOCKS5/HTTP proxy, timing jitter, UA rotation, decoy requests, body padding — base IP never exposed |
| **ML / AI** | Isolation Forest, One-Class SVM, ARIMA/Holt-Winters forecasting, ROS-style AI node graph, NLP parsing |
| **Remote Control** | WhatsApp, SMS (Twilio), Telegram, Discord, Slack — per-user permissions, rate limiting, webhook verification |
| **Dashboard** | Zero-dep async HTTP dashboard with live Fleet Map canvas, threat feed, and agent drill-down |
| **Plugin System** | Extensible registry for custom sensors, models, and dashboard components |

## Project Structure

## Quick Start

```bash
pip install -e ".[dev]"
network-guardian          # interactive CLI
python _start_dashboard.py  # web dashboard at http://127.0.0.1:8080
```

## Fleet Agents

```bash
# Probe — periodic scanner that phones home
python -m network_guardian.agent.probe --base http://BASE_IP:8080 --key FLEET_KEY --tor --stealth

# Sentinel — persistent stay-behind bot
python -m network_guardian.agent.sentinel --base http://BASE_IP:8080 --key FLEET_KEY --tor --stealth
```

Covert flags: `--tor`, `--proxy socks5://...`, `--stealth` (30–300s jitter + decoys). Base IP is never exposed on the wire.

## Remote Control (WhatsApp / SMS / Telegram / Discord / Slack)

```bash
export TWILIO_ACCOUNT_SID=ACxxxx  TWILIO_AUTH_TOKEN=your_token  ALLOWED_NUMBERS=+1YOURPHONE
python whatsapp_server.py          # expose with: ngrok http 8765
```

Send `ping` → `pong`. Permissions: READ / EXECUTE / ADMIN.  
Key commands: `status`, `ids scan <text>`, `ips block <ip>`, `audit <target>`, `explore <subnet>`, `train anomaly`.

## Testing

```bash
pytest tests/ -v   # 388 tests, all passing
```

## Requirements

- Python 3.11+, zero external ML deps
- Root/admin for network scanning (ping, Nmap)
- Optional: `pyyaml`, `twilio`, `cmdop`, `cmdop-bot`, `openclaw`

## Secret Hygiene

Never commit real credentials. Use env vars or platform secrets. Run `grep -RInE "(token|secret|password|fleet_key)" .` before every push. Keep the repo **private**.

## License

This project is proprietary and closed-source.

- Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
- Legal owner: Wolf-Pak Innovations LLC (Michigan, USA).
- No permission is granted to use, copy, modify, distribute, sublicense, sell, or create derivatives without prior written authorization.
- Commercial use requires a separate paid commercial license agreement.
- See LICENSE and COPYRIGHT for full terms.

## Legal and Commercial Ops

- Federal filing checklist packet: FEDERAL_COPYRIGHT_REGISTRATION_PACKET.txt
- Commercial license agreement template: COMMERCIAL_EULA.txt
- Inbound commercial request intake form: LICENSE_REQUEST_INTAKE_FORM.txt
- Internal pricing and tier matrix: PRICING_TIER_MATRIX.txt
