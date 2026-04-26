# Deployment

---

## Local Development

### Requirements

- Python 3.11+
- macOS or Linux (Windows untested)
- Root/admin for full network scanning (ping, Nmap)
- Optional: Tor (`brew install tor`) for covert agent comms

### Setup

```bash
git clone <repo>
cd "Network Guardian"
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Starting the Dashboard

```bash
python _start_dashboard.py
# Dashboard at http://127.0.0.1:8080
# Login: admin / <password>
```

### Running a Probe Agent (local)

```bash
python -m network_guardian.agent.probe \
  --base http://127.0.0.1:8080 \
  --key $(python3 -c "from network_guardian.interface._fleet import FleetStore; from pathlib import Path; import os; print(FleetStore(Path.home()/'.network_guardian').fleet_key)")
```

Or set the key manually after getting it from the Fleet page → "Copy Fleet Key".

### Interactive CLI

```bash
network-guardian
```

Provides an interactive REPL for all engine operations.

---

## Heroku Deployment

### Prerequisites

- [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli) installed and logged in
- Git repository initialized

### First-Time Deploy

```bash
# Create the app
heroku create network-guardian

# Generate and set a permanent fleet key
heroku config:set FLEET_KEY=$(python3 -c "
import secrets, base64
print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
")

# Deploy
git push heroku main
```

### Subsequent Deploys

```bash
git push heroku main
```

### View Logs

```bash
heroku logs --tail
```

### Current App

| Field | Value |
|---|---|
| App name | `network-guardian` |
| URL | https://network-guardian-cc8900c70290.herokuapp.com |
| Stack | Heroku-24 |
| Python | 3.11 (via `.python-version`) |
| Current release | v18 |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | Heroku-only | HTTP port (Heroku sets this automatically) |
| `FLEET_KEY` | Yes | HMAC key for fleet agent authentication. Must be set before deploying. |
| `NETWORK_GUARDIAN_API_KEY` | No | Alternative API key (legacy) |
| `TWILIO_ACCOUNT_SID` | Remote control | Twilio SID for SMS/WhatsApp |
| `TWILIO_AUTH_TOKEN` | Remote control | Twilio auth token |
| `ALLOWED_NUMBERS` | Remote control | Comma-separated E.164 phone numbers |

### Setting Environment Variables

**Heroku:**
```bash
heroku config:set FLEET_KEY=your_key_here
heroku config:set TWILIO_ACCOUNT_SID=ACxxxxxxxxx
heroku config:set TWILIO_AUTH_TOKEN=your_token
heroku config:set ALLOWED_NUMBERS=+12125551234,+13105555678
```

**Local (`.env` file — never commit):**
```bash
export FLEET_KEY=your_key_here
export TWILIO_ACCOUNT_SID=ACxxxxxxxxx
```

---

## Running Fleet Agents Against Heroku

```bash
python -m network_guardian.agent.probe \
  --base https://YOUR-HEROKU-APP.herokuapp.com \
  --key YOUR_FLEET_KEY \
  --stealth
```

> Get `YOUR_FLEET_KEY` from the dashboard Fleet page → "Copy Fleet Key" (admin login required).

The fleet key is permanent via the `FLEET_KEY` Heroku config var — it survives dyno restarts.

---

## Docker Deployment

A `Dockerfile` and `docker-compose.yml` are included:

```bash
# Build and run
docker-compose up --build

# Dashboard at http://localhost:8080
```

**Important:** Set `FLEET_KEY` in your `docker-compose.yml` or as an environment variable before starting.

---

## File Structure

```
Network Guardian/
├── _start_dashboard.py       # Standalone dashboard launcher
├── _rebuild_all.py           # Full rebuild script
├── config.example.yaml       # Configuration template
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh
├── pyproject.toml            # Package metadata and entry points
├── sonar-project.properties  # SonarQube config
├── documentation/            # This folder
├── incident_reports/         # Auto-generated incident reports
│   └── INCIDENT_REPORT_2026-04-13.md
├── network_guardian/
│   ├── agent/                # Probe + Sentinel + ReAct + Threat Analyzer
│   ├── ai/                   # Anomaly detection, forecasting, NLP, automation
│   ├── auditor/              # Compliance auditing
│   ├── automator/            # Task automation
│   ├── cloaking/             # IP/MAC cloaking
│   ├── config/               # Configuration dataclasses
│   ├── core/                 # Engine, EventBus, PluginRegistry
│   ├── explorer/             # Network topology discovery
│   ├── ids/                  # Intrusion detection
│   ├── interface/            # Dashboard, Fleet, Team, Security, Controls
│   ├── ips/                  # Intrusion prevention
│   ├── models/               # Data models (Network, etc.)
│   ├── monitor/              # Network traffic monitoring
│   ├── remote/               # Remote control (WhatsApp, SMS, etc.)
│   ├── sensors/              # Ping, port scan, system metrics
│   ├── utils/                # Logging utilities
│   └── wolfpak/              # Wolfpak admin client registry
└── tests/                    # 388 tests
```

---

## Package Entry Points

Defined in `pyproject.toml`:

| Command | Module |
|---|---|
| `network-guardian` | `network_guardian.__main__:main` |
| `ng-probe` | `network_guardian.agent.probe:main` |
| `ng-sentinel` | `network_guardian.agent.sentinel:main` |

---

## Remote Control (WhatsApp / SMS / Telegram / Discord / Slack)

```bash
export TWILIO_ACCOUNT_SID=ACxxxx
export TWILIO_AUTH_TOKEN=your_token
export ALLOWED_NUMBERS=+1YOURPHONE

python whatsapp_server.py
# Expose via: ngrok http 8765
# Set Twilio webhook to: https://your-ngrok-url.ngrok.io/webhook
```

### Supported Commands

| Command | Description | Permission |
|---|---|---|
| `ping` | Health check | READ |
| `status` | Engine status | READ |
| `ids scan <text>` | Run IDS scan on text | EXECUTE |
| `ips block <ip>` | Block an IP | EXECUTE |
| `ips unblock <ip>` | Unblock an IP | EXECUTE |
| `audit <target>` | Run compliance audit | EXECUTE |
| `explore <subnet>` | Network discovery | EXECUTE |
| `train anomaly` | Retrain anomaly detectors | ADMIN |
| `fleet` | List registered agents | READ |
| `help` | Show command list | READ |

---

## Secret Hygiene

Before every push, run:

```bash
grep -RInE "(token|secret|password|fleet_key|api_key)" . \
  --include="*.py" --include="*.yaml" --include="*.json" \
  --exclude-dir=".venv" --exclude-dir=".git"
```

**Never commit:**
- `FLEET_KEY` values
- Twilio credentials
- Auth tokens or session secrets
- The `wolfpak_team.json` file

Keep the repository **private**.

---

## Testing

```bash
pytest tests/ -v
# 388 tests, all passing
```

Test files:

| File | Coverage |
|---|---|
| `test_ai_deep.py` | ML models, forecasting |
| `test_architecture.py` | Engine subsystem wiring |
| `test_core.py` | Engine, EventBus, Config |
| `test_remote.py` | Remote control commands |
| `test_security_systems.py` | IDS rules, IPS policies |
| `test_step4.py` | Step-by-step integration |
| `test_wifi_stealth.py` | WiFi scanning, cloaking |
