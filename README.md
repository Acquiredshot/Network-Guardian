# Network Guardian

Autonomous network auditing, intrusion detection/prevention, and system monitoring assistant for IT professionals, network administrators, and system engineers. Powered by a pure-Python ML stack and a ROS-inspired reactive node framework — zero external ML dependencies required. Controllable remotely via WhatsApp, SMS, Telegram, Discord, and Slack.

## Features

- **Autonomous Network Auditing** — Scan and audit network infrastructure for vulnerabilities, misconfigurations, and performance bottlenecks
- **Intrusion Detection System (IDS)** — 15 built-in signature rules, regex + keyword payload analysis, alert severity scoring, brute-force anomaly detection, multi-stage attack correlation, and alert suppression
- **Intrusion Prevention System (IPS)** — IP blocklist/allowlist, rate limiting, quarantine zones, auto-respond to IDS alerts, time-based block expiry
- **IP Cloaking** — MAC address masking, deterministic IP obfuscation with unmask, source address rotation (round-robin/random), decoy IP generation, named identity profiles, proxy chain support
- **Fleet Agent System** — Deploy field agents (`ng-probe`) and stay-behind sentinels (`ng-sentinel`) that monitor remote networks and phone home to the base station
- **Covert Communications** — All agent-to-base traffic routed through Tor/SOCKS5/HTTP proxy with timing jitter, rotating browser User-Agents, decoy requests, and body padding — base station IP never exposed to network observers
- **ML-Powered Anomaly Detection** — Isolation Forest, One-Class SVM, and ensemble detectors score network telemetry in real time
- **Predictive Forecasting** — ARIMA, seasonal decomposition (Prophet-style), and Holt-Winters models forecast metric trends
- **Smart Task Automation** — Bayesian success estimation, failure-streak backoff, and finding-to-task recommendation engine
- **ROS-Inspired AI Node Graph** — Reactive publish-subscribe compute graph with independent AI processing nodes
- **ML Training Pipeline** — End-to-end training orchestration with synthetic data generation, model registry, and structured reporting
- **NLP Command Parsing** — Natural language intent parsing, log analysis, and finding summarisation
- **Sensor Layer** — Unified interface over ping, port scanning, Nmap, and system metrics collection
- **Remote Access** — Control Network Guardian from your phone via WhatsApp/SMS (Twilio), Telegram, Discord, or Slack (CMDOP/OpenClaw), with per-user permissions, rate limiting, and webhook verification
- **Interactive Interface** — Human-AI collaboration through CLI and zero-dependency async web dashboard
- **System Monitoring** — Real-time monitoring with z-score anomaly detection and intelligent alerting
- **Network Exploration** — Discover and map network topology autonomously
- **Plugin System** — Extensible base class and registry for custom sensors, models, and dashboard components

## Project Structure

```
network_guardian/
├── core/                  # Engine orchestrator, event bus, plugin system
│   ├── engine.py          # Central engine — wires all subsystems
│   ├── events.py          # Async pub-sub EventBus
│   └── plugins.py         # Plugin base class and registry
├── agent/                 # Fleet field agents
│   ├── probe.py           # ng-probe — periodic network scanner + reporter
│   ├── sentinel.py        # ng-sentinel — persistent stay-behind monitoring bot
│   ├── covert_comms.py    # Covert channel — Tor/SOCKS5/HTTP proxy + obfuscation
│   └── react_agent.py     # ReAct threat reasoning agent (observe-reason-act-learn)
├── ai/                    # AI & machine learning subsystem
│   ├── __init__.py        # AIEngine — model registry, forecasting, fleet analysis
│   ├── anomaly.py         # IsolationForest, OneClassSVM, EnsembleDetector
│   ├── forecasting.py     # ARIMA, SeasonalDecomposer, HoltWinters forecasters
│   ├── audit_analyzer.py  # ML-powered host risk scoring with port-risk knowledge base
│   ├── smart_automation.py# Task recommendation & scheduling engine
│   ├── nodes.py           # ROS-inspired AINode framework and NodeGraph
│   ├── training.py        # TrainingPipeline, ModelRegistry, TrainingReport
│   ├── datasets.py        # Synthetic generators, CSV loader, feature utilities
│   └── nlp.py             # NLP intent parsing, log analysis, summarisation
├── ids/                   # Intrusion Detection System
│   └── __init__.py        # Rules engine, payload analysis, correlation, anomaly detection
├── ips/                   # Intrusion Prevention System
│   └── __init__.py        # Blocklist, allowlist, rate limiting, quarantine, auto-respond
├── cloaking/              # IP Cloaking system
│   └── __init__.py        # IP masking, source rotation, decoys, identities, proxy chains
├── remote/                # Remote access channels
│   └── __init__.py        # WhatsApp, SMS, Telegram, Discord, Slack — permissions & routing
├── sensors/               # Sensor layer (ping, port scanner, Nmap, system metrics)
├── auditor/               # Network auditing and vulnerability scanning
├── monitor/               # System monitoring and anomaly detection
├── explorer/              # Network discovery and topology mapping
├── automator/             # Task automation and scheduling
├── interface/             # CLI and web dashboard
│   ├── __init__.py        # InteractiveCLI with full command set
│   ├── dashboard.py       # Zero-dependency async HTTP dashboard + Fleet API
│   └── _fleet.py          # Fleet store, agent registry, Fleet Command UI
├── config/                # YAML + env var configuration management
├── models/                # Shared data models (Host, Finding, Metric)
└── utils/                 # Logging and shared utilities

whatsapp_server.py         # Standalone WhatsApp webhook server for Twilio testing
```

## Security Systems

### Intrusion Detection System (IDS)

The IDS provides real-time threat detection with multiple analysis layers:

- **Signature Rules** — 15 built-in rules covering SYN scans, ICMP sweeps, service enumeration, brute force, SQL injection, XSS, path traversal, command injection, DNS tunnelling, C2 beacons, data exfiltration, privilege escalation, lateral movement, and cryptomining
- **Payload Analysis** — Regex and keyword matching against network payloads
- **Anomaly Detection** — Connection-rate tracking with configurable thresholds for brute-force detection
- **Attack Correlation** — Multi-stage attack chain identification across related alerts
- **Alert Suppression** — Deduplication of repeated alerts from the same source
- **Event Bus Integration** — Alerts automatically published for IPS auto-response

### Intrusion Prevention System (IPS)

The IPS actively responds to threats detected by the IDS:

- **IP Blocklist** — Block malicious IPs with optional time-based expiry
- **Allowlist** — Protect trusted IPs from accidental blocking
- **Rate Limiting** — Per-IP connection rate enforcement
- **Quarantine** — Isolate suspicious IPs for further analysis
- **Auto-Respond** — Automatically block IPs that trigger IDS alerts (configurable)
- **Policy Modes** — Permissive, strict, and custom response policies

### IP Cloaking

Protect scanner identity during network operations:

- **MAC Masking** — Deterministic IP-to-masked-IP mapping with full unmask support
- **Source Rotation** — Round-robin or random source address selection from a configurable pool
- **Decoy Generation** — Generate realistic decoy IPs for scan obfuscation
- **Named Identities** — Create, activate, and manage multiple scanning identities
- **Proxy Chains** — Route through proxy chains for additional anonymity
- **Scan Preparation** — Automatically apply active identity + decoys to scan configurations

## Fleet Agent System

Deploy autonomous field agents that monitor remote networks and report back to your base station.

### Field Probe (`ng-probe`)

A periodic collector that scans its local environment and phones home on a configurable interval:

```bash
# Deploy on a remote machine
python -m network_guardian.agent.probe \
  --base http://BASE_IP:8080 \
  --key FLEET_KEY \
  --interval 60 \
  --tor                      # Route via Tor (or --proxy socks5://127.0.0.1:9050)
  --stealth                  # Max jitter + decoys
```

Collects and reports: WiFi networks, discovered hosts, open ports, system metrics, gateway info, and full ReAct threat analysis.

### Sentinel Bot (`ng-sentinel`)

A persistent stay-behind agent with continuous monitoring loops:

```bash
# Plant on a target network
python -m network_guardian.agent.sentinel \
  --base http://BASE_IP:8080 \
  --key FLEET_KEY \
  --proxy socks5://127.0.0.1:9050   # or --tor
  --stealth
```

| Loop | What it does |
|---|---|
| **WiFi Watcher** | Tracks SSIDs appearing/disappearing, signal drift, rogue AP detection, channel congestion |
| **Flow Monitor** | Watches TCP/UDP flows, detects new external endpoints, bandwidth anomalies |
| **Adaptive Engine** | Adjusts sensitivity and scan intervals based on learned environment baseline |
| **Base Reporter** | Streams intelligence back with priority levels: routine (60s), alert (immediate) |

### Fleet Command Dashboard

The `/fleet` page shows all deployed agents in real time:

- **Agent cards** with status (online/stale/offline), IP, WiFi/host counts, ReAct threat score
- **Sentinel badge** — continuous monitoring bots shown with cyan `🛡 Sentinel` tag and WiFi change / rogue AP counters
- **Covert badge** — `🔒 Tor` (green) / `🔒 Proxy` (blue) / `🔓 Direct` (gray) per agent showing anonymization state
- **Fleet KPIs** — total agents, online/stale/offline counts, threat count, ReAct agents, WiFi nets, hosts, covert count
- **Fleet Threat Intelligence** — aggregated ReAct diagnostics across all agents
- **Detail overlay** — click any agent for full drill-down: covert channel info, threats, ReAct log, sentinel intelligence, WiFi/host inventory

#### Fleet Map

Live animated canvas network diagram rendered at 60 fps via `requestAnimationFrame`:

| Element | Description |
|---|---|
| **Dark radar grid** | Subtle dot-grid background gives a tactical display feel |
| **Pulsing base station** | Central node with animated blue halo and radial glow |
| **Gradient connection lines** | Animated dashed lines flow from base to each agent in the agent's status color |
| **Agent glow rings** | Online agents emit a breathing glow; offline agents show a static red ring |
| **Threat score arc** | A colored progress arc (green → yellow → orange → red) wraps each node showing exact ReAct threat score out of 100 |
| **Sentinel orbit ring** | Animated dashed cyan orbit circle for persistent sentinel bots |
| **Indicator dots** | Purple (top-right) = ReAct active; Cyan (top-left) = Sentinel; Green/Blue (bottom-right) = Covert/Tor |
| **Legend bar** | Inline color legend below the canvas |

## Covert Communications

All agent-to-base HTTP traffic is routed through an anonymization layer so the base station IP is never visible to anyone watching the bot's network traffic.

### How it works

| Layer | Protection |
|---|---|
| **Tor SOCKS5** | Pure-Python tunnel (no PySocks dep) — TCP connects to proxy, DNS resolves at exit node — base IP fully hidden |
| **HTTP/HTTPS proxy** | Standard proxy via Python's built-in `urllib.ProxyHandler` (works with Privoxy on port 8118) |
| **Auto-detection** | Automatically probes 9050/9150 for Tor SOCKS5 and 8118 for Privoxy — zero config if Tor is running |
| **Timing jitter** | Random delay (default 3–25s, stealth mode 30–300s) before each transmission breaks timing correlation |
| **UA rotation** | Cycles through 8 real browser User-Agents — traffic looks like normal browsing |
| **Decoy requests** | Fires 2–4 fake GETs to innocuous public URLs around every real report to mask traffic pattern |
| **Body padding** | Adds random `_t` field to JSON payloads to break size fingerprinting |
| **Safe logging** | Base URL SHA-256 hashed in all log output — never appears in plaintext |

### Agent CLI flags

All flags available on both `ng-probe` and `ng-sentinel`:

```bash
--proxy socks5://127.0.0.1:9050   # Explicit SOCKS5 proxy (also: http://host:port)
--proxy http://proxy.corp:8080    # HTTP proxy
--tor                             # Force Tor — fails if Tor not running
--stealth                         # Ghost mode: 30–300s jitter, 4 decoys, max suppression
--no-jitter                       # Disable random delays (for testing)
```

### Environment variables

```bash
export NG_PROXY=socks5://127.0.0.1:9050  # Proxy URL
export NG_TOR=1                           # Force Tor
export NG_STEALTH=1                       # Stealth mode
export NG_JITTER=0                        # Disable jitter
export NG_DECOYS=0                        # Disable decoys
```

### Covert status in Fleet UI

Every agent report embeds its current covert channel state. The Fleet Command dashboard shows:
- **🔒 Covert** KPI tile — how many agents are using proxy/Tor
- Per-agent chip — `🔒 Tor`, `🔒 Proxy`, or `🔓 Direct` with jitter range and decoy count
- Detail overlay — full channel breakdown or red warning if running unprotected
- Map — green (Tor) or blue (proxy) lock dot on each agent node

## Remote Access

Control Network Guardian from your phone or messaging platform. The remote access module supports multiple channels with unified permission management and rate limiting.

### Supported Channels

| Channel | Provider | Protocol |
|---|---|---|
| WhatsApp | Twilio WhatsApp Business API | Webhook (TwiML) |
| SMS | Twilio Programmable SMS | Webhook (TwiML) |
| Telegram | CMDOP Bot | Bot API |
| Discord | CMDOP Bot | Gateway API |
| Slack | CMDOP Bot | Events API |

### Remote Commands

All engine subsystems are accessible remotely:

```
ping              — Connectivity check
help              — List all commands
status            — Engine status
sensors list      — List available sensors
sensors collect   — Collect sensor readings
ids status        — IDS rules and alert count
ids rules         — List all IDS rules
ids scan <text>   — Analyse payload for threats
ips status        — IPS blocklist/quarantine info
ips block <ip>    — Block an IP address
ips unblock <ip>  — Unblock an IP address
cloak status      — Cloaking system status
cloak mask        — Show current IP mask
cloak identity    — Active identity info
cloak decoys      — Generate decoy IPs
audit <target>    — Run network audit
explore <subnet>  — Discover hosts
monitor start     — Start monitoring
monitor stop      — Stop monitoring
ai recommend      — AI recommendations
ai classify       — AI classification
train anomaly     — Train anomaly detection model
train forecast    — Train forecasting model
```

### WhatsApp Setup

```bash
# 1. Set environment variables
$env:TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxx"
$env:TWILIO_AUTH_TOKEN   = "your_auth_token"
$env:ALLOWED_NUMBERS     = "+1YOURPHONE"

# 2. Start the server
python whatsapp_server.py

# 3. Expose with ngrok
ngrok http 8765

# 4. Configure Twilio webhook to https://xxxx.ngrok-free.app/whatsapp
# 5. Join the Twilio WhatsApp Sandbox from your phone
# 6. Send "ping" to the sandbox number — you'll get "pong" back
```

### Permissions

Three permission levels control remote access:

| Level | Access |
|---|---|
| **READ** | `status`, `sensors list`, `ids status`, `cloak status` |
| **EXECUTE** | All READ commands + `audit`, `explore`, `ids scan`, `sensors collect` |
| **ADMIN** | Full access including `monitor start/stop`, `ips block/unblock`, `train` |

## GitHub Privacy and Secret Hygiene

Use these rules before every push to keep the repository private and prevent accidental credential leaks:

1. Keep repository visibility set to **Private**.
2. Never commit runtime secrets from `~/.network_guardian/` (team store, fleet keys, session/token material).
3. Use placeholders in docs and examples (`your_auth_token`, `ACxxxxxxxxxxxx`) instead of real values.
4. Rotate and replace any credential immediately if it is ever exposed in logs, screenshots, commits, or chat.
5. Verify before push:

```bash
git status
git diff --staged
grep -RInE "(token|secret|api[_-]?key|fleet_key|password|twilio_auth_token)" README.md network_guardian pyproject.toml config.example.yaml
```

6. Use local env vars or platform secrets for runtime values; do not hard-code credentials in source files.

## AI Node Graph

Network Guardian uses a ROS-inspired reactive compute graph where independent AI nodes communicate via the shared event bus:

```
sensor.metrics ──► AnomalyDetectionNode ──► ai.anomaly_scored
sensor.timeseries ──► ForecastNode ──► ai.forecast_ready
scanner.hosts_discovered ──► AuditAnalysisNode ──► ai.risk_profiles
                                                 ──► ai.audit_findings
ai.audit_findings ──► TaskRecommendationNode ──► ai.task_recommendations
```

Nodes are lifecycle-managed (`start` / `stop`), rate-limitable, and expose health telemetry. The `NodeGraph` orchestrates the full graph and integrates with the engine lifecycle.

## ML Models

All ML implementations are **pure Python with zero external dependencies**:

| Model | Module | Purpose |
|---|---|---|
| Isolation Forest | `ai.anomaly` | Unsupervised anomaly detection via random isolation trees |
| One-Class SVM | `ai.anomaly` | RBF kernel density anomaly scoring |
| Ensemble Detector | `ai.anomaly` | Score averaging across multiple detectors |
| ARIMA | `ai.forecasting` | Auto-regressive integrated moving average forecasting |
| Seasonal Decomposer | `ai.forecasting` | Prophet-style trend + seasonality decomposition |
| Holt-Winters | `ai.forecasting` | Triple exponential smoothing with additive seasonality |
| Audit Analyzer | `ai.audit_analyzer` | Port-risk knowledge base + fleet anomaly detection |
| Smart Automation | `ai.smart_automation` | Bayesian task recommendation with failure backoff |

## Training Pipeline

```python
from network_guardian.ai.training import TrainingPipeline

pipeline = TrainingPipeline()

# Train anomaly detection on synthetic network traffic
report = pipeline.run_full_anomaly_pipeline(n_normal=800, n_anomaly=50)
print(report.summary())  # accuracy, precision, recall, F1

# Train time-series forecasting
report = pipeline.run_full_forecast_pipeline(method="arima", length=720)
print(report.summary())  # MAE, RMSE, coverage
```

Custom datasets can be loaded via `CSVDatasetLoader` for external data (UCI ML Repository, Kaggle, etc.).

## Quick Start

```bash
pip install -e ".[dev]"
network-guardian --help
```

### CLI Commands

```
guardian> help
  help         Show available commands
  audit        Run a network audit
  explore      Discover hosts in a subnet
  monitor      Start/stop monitoring
  tasks        List or run automated tasks
  ai           AI commands (recommend, classify, models)
  ask          Natural language query
  sensors      Show sensor status
  dashboard    Start/stop the web dashboard
  train        Train ML models (anomaly or forecast)
  nodes        AI node graph (start, stop, status, topology)
  datasets     Dataset tools (generate, stats)
  ids          Intrusion Detection System (start, stop, status, scan)
  ips          Intrusion Prevention System (start, stop, status, block, unblock)
  cloak        IP Cloaking (mode, mask, identity, decoys, status)
  remote       Remote access (status, channels, users, pipeline, start, stop)
  status       Show engine status
  quit         Exit Network Guardian
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

**294 tests** across 6 test modules:

| Module | Tests | Coverage |
|---|---|---|
| `test_core.py` | Core engine, config, event bus, plugins | Engine lifecycle, pub-sub, plugin registry |
| `test_architecture.py` | CLI, auditor, explorer, monitor, sensors | End-to-end system integration |
| `test_ai_deep.py` | All ML models, NLP, smart automation | Anomaly detection, forecasting, NLP parsing |
| `test_step4.py` | Node graph, training pipeline, datasets | AI nodes, model training, data generation |
| `test_security_systems.py` | IDS, IPS, IP Cloaking | Rules, alerts, blocklist, masking, identities |
| `test_remote.py` | Remote access, all channels, permissions | WhatsApp, SMS, CMDOP, routing, rate limiting |

## Optional Dependencies

```bash
# Remote access (WhatsApp/SMS via Twilio + Telegram/Discord/Slack via CMDOP)
pip install -e ".[remote]"

# Development (pytest, ruff)
pip install -e ".[dev]"
```

## Requirements

- Python 3.11+
- Zero external ML dependencies — all algorithms are pure Python
- Administrative/root access for network scanning features (ping, Nmap)
- Optional: `pyyaml` for YAML config loading
- Optional: `twilio` for WhatsApp/SMS remote access
- Optional: `cmdop`, `cmdop-bot`, `openclaw` for Telegram/Discord/Slack remote access
