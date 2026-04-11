# Network Guardian

Autonomous network auditing, intrusion detection/prevention, and system monitoring assistant for IT professionals, network administrators, and system engineers. Powered by a pure-Python ML stack and a ROS-inspired reactive node framework — zero external ML dependencies required. Controllable remotely via WhatsApp, SMS, Telegram, Discord, and Slack.

## Features

- **Autonomous Network Auditing** — Scan and audit network infrastructure for vulnerabilities, misconfigurations, and performance bottlenecks
- **Intrusion Detection System (IDS)** — 15 built-in signature rules, regex + keyword payload analysis, alert severity scoring, brute-force anomaly detection, multi-stage attack correlation, and alert suppression
- **Intrusion Prevention System (IPS)** — IP blocklist/allowlist, rate limiting, quarantine zones, auto-respond to IDS alerts, time-based block expiry
- **IP Cloaking** — MAC address masking, deterministic IP obfuscation with unmask, source address rotation (round-robin/random), decoy IP generation, named identity profiles, proxy chain support
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
│   └── dashboard.py       # Zero-dependency async HTTP dashboard
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
