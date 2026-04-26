# Architecture

## Overview

Network Guardian is a **pure Python 3.11** autonomous security platform with zero heavy external ML dependencies. It is built on an asyncio event-driven core and communicates between components through a central `EventBus`.

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                         Engine (core)                           │
│                                                                 │
│  EventBus ──────────────────────────────────────────────────┐   │
│                                                             │   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │   │
│  │   IDS    │  │   IPS    │  │ Monitor  │  │ Auditor  │───┘   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Explorer │  │Automator │  │  AI Eng  │  │  NLP Eng │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │Cloaking  │  │WiFiStealth│ │  Remote  │  │Dashboard │       │
│  └──────────┘  └──────────┘  └──────────┘  └────┬─────┘       │
└───────────────────────────────────────────────────┼─────────────┘
                                                    │ HTTP
                                         ┌──────────▼──────────┐
                                         │      Browser UI      │
                                         └─────────────────────┘

                    ┌─────────────────────────┐
                    │      Fleet Agents        │
                    │                          │
                    │  ┌──────────────────┐    │
                    │  │  ng-probe        │    │
                    │  │  (periodic scan) │    │
                    │  └──────────────────┘    │
                    │                          │
                    │  ┌──────────────────┐    │
                    │  │  ng-sentinel     │    │
                    │  │  (stay-behind)   │    │
                    │  └──────────────────┘    │
                    └────────────┬────────────┘
                                 │ HTTPS (HMAC)
                    ┌────────────▼────────────┐
                    │       FleetStore         │
                    │  (per-agent data store)  │
                    └─────────────────────────┘
```

---

## Core Engine (`network_guardian/core/engine.py`)

The `Engine` class is the central orchestrator. All subsystems are lazy-loaded via Python properties so they only instantiate when first accessed.

```python
class Engine:
    config: Config
    event_bus: EventBus
    plugins: PluginRegistry
```

### Subsystem Properties

| Property | Class | Purpose |
|---|---|---|
| `engine.auditor` | `Auditor` | Compliance and security auditing |
| `engine.monitor` | `Monitor` | Network traffic monitoring |
| `engine.explorer` | `Explorer` | Network topology discovery |
| `engine.automator` | `Automator` | Task automation |
| `engine.ai` | `AIEngine` | ML inference engine |
| `engine.nlp` | `NLPEngine` | Command and log NLP parsing |
| `engine.ids` | `IntrusionDetectionSystem` | Signature + anomaly IDS |
| `engine.ips` | `IntrusionPreventionSystem` | Automated threat response |
| `engine.cloaking` | `IPCloakingSystem` | IP/MAC obfuscation |
| `engine.wifi_stealth` | `WiFiStealthSystem` | WiFi stealth operations |
| `engine.remote` | `RemoteAccessManager` | WhatsApp/SMS/Telegram control |
| `engine.dashboard` | `Dashboard` | Async HTTP web dashboard |
| `engine.sensors` | `SensorRegistry` | Ping, port scan, system metrics |
| `engine.node_graph` | `NodeGraph` | ROS-style compute graph |
| `engine.training` | `TrainingPipeline` | ML model training pipeline |

### Lifecycle

```python
await engine.start()   # Initialize all subsystems, create data directory
# ... running ...
await engine.stop()    # Graceful shutdown
```

---

## Configuration (`network_guardian/config/__init__.py`)

All configuration is loaded from `config.yaml` (or `config.example.yaml` as template) with environment variable overrides using the prefix `NETWORK_GUARDIAN_`.

### Config Hierarchy

```python
Config
├── scan: ScanConfig
│   ├── timeout: float = 5.0
│   ├── max_concurrent: int = 50
│   ├── port_range: str = "1-1024"
│   ├── ping_count: int = 3
│   └── subnet_masks: list[str] = ["24"]
├── monitor: MonitorConfig
│   ├── poll_interval: float = 30.0
│   ├── anomaly_threshold: float = 2.0   # standard deviations
│   ├── retention_hours: int = 168       # 7 days
│   └── alert_cooldown: float = 300.0    # seconds
├── security: SecurityConfig
│   ├── encrypt_reports: bool = True
│   ├── api_key_env: str = "NETWORK_GUARDIAN_API_KEY"
│   ├── max_login_attempts: int = 5
│   └── session_timeout: int = 3600
├── log_level: str = "INFO"
└── data_dir: Path = ~/.network_guardian
```

### Loading

```python
config = Config.load("config.yaml")   # from file
config = Config.load(None)            # defaults + env var overrides
```

---

## Event Bus (`network_guardian/core/events.py`)

All subsystems communicate asynchronously via the `EventBus`. This decouples components — IDS fires an event, IPS subscribes and reacts.

### Event Topics

| Topic | Publisher | Subscriber(s) |
|---|---|---|
| `audit.finding` | Auditor | Dashboard |
| `monitor.anomaly` | Monitor | Dashboard, AI Engine |
| `ai.anomaly_detected` | AI Engine | Dashboard |
| `ai.assessment` | AI Monitor Loop | Dashboard |
| `ai.spike.*` | AI Monitor Loop | Dashboard |
| `ids.alert` | IDS | IPS, Dashboard |
| `ids.started` | IDS | Dashboard |
| `ids.correlation` | IDS | Dashboard |
| `ips.block` | IPS | Dashboard |
| `ips.unblock` | IPS | Dashboard |
| `ips.rate_limit` | IPS | Dashboard |
| `ips.quarantine` | IPS | Dashboard |
| `ips.quarantine_release` | IPS | Dashboard |
| `ips.started` | IPS | Dashboard |
| `explorer.discovery_complete` | Explorer | Dashboard |
| `automator.task_complete` | Automator | Dashboard |

### Usage

```python
# Subscribe
engine.event_bus.subscribe("ids.alert", my_handler)

# Publish
engine.event_bus.publish(Event(topic="ids.alert", data={...}))
```

---

## Plugin System (`network_guardian/core/plugins.py`)

The `PluginRegistry` allows custom sensors, models, and dashboard components to be registered at runtime.

```python
engine.plugins.register("my_sensor", MySensor)
sensor = engine.plugins.get("my_sensor")
```

---

## Data Persistence

| Component | Storage Path | Format |
|---|---|---|
| Config | `~/.network_guardian/` | YAML |
| Fleet data | `~/.network_guardian/fleet.json` | JSON |
| Team/auth | `~/.network_guardian/wolfpak_team.json` | JSON |
| Agent baselines | `~/.ng_agent/baselines.json` | JSON |
| Agent threat history | `~/.ng_agent/threat_history.json` | JSON |
| Agent threat reports | `~/.ng_agent/threat_reports.json` | JSON |
| Agent identity | `~/.ng_agent/.ng_agent_id` | JSON |
| Auth token | `~/.ng_agent/wolfpak_auth.json` | JSON (mode 0600) |
| Incident reports | `~/.ng_agent/incident_reports/` | Markdown |
| Incident reports (project) | `./incident_reports/` | Markdown |

---

## Security Model

- All dashboard routes require session authentication (HMAC-signed cookie)
- Fleet agent endpoints use HMAC-SHA256 with the fleet key
- Session secret is generated fresh per install (`secrets.token_urlsafe`)
- Rate limiting: per-IP token bucket on all API endpoints
- Brute-force protection: exponential back-off on `/api/auth/login`
- CSP nonce: regenerated on each server start, applied to all inline scripts
- Fleet key: stored as `FLEET_KEY` environment variable (survives Heroku restarts)
