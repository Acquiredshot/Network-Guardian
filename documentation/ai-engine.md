# AI Engine

The AI Engine is a 24/7 autonomous monitoring system that combines a background asyncio loop, ML anomaly detectors, time-series forecasting, and a real-time SSE push stream. It requires zero external ML dependencies — all algorithms are implemented in pure Python.

---

## 24/7 Background Monitor Loop

### Overview

When the dashboard starts, `Dashboard.start()` creates an asyncio background task:

```python
self._ai_monitor_task = asyncio.create_task(self._ai_monitor_loop())
```

This task runs for the lifetime of the server, ticking every **10 seconds** regardless of whether any HTTP clients are connected.

### Tick Cycle (`_ai_monitor_tick`)

On every tick, the monitor:

1. Iterates every registered fleet agent
2. Reads the latest `last_diagnostics` from each agent
3. Appends new data points to rolling time-series (100-point window)
4. Runs four anomaly detection rules
5. Runs spike detection across all metrics
6. Processes per-agent `threat_history` into AI events
7. Emits typed `ai.*` events into `_ai_state["ai_events"]` and `_recent_events`

### Rolling Time-Series Metrics

Each metric maintains a **100-point rolling window** (oldest data automatically dropped):

| Metric Key | Source | Description |
|---|---|---|
| `threat_score` | `last_diagnostics.threat_score` | 0–100 composite threat score |
| `connections` | `len(last_diagnostics.network_connections)` | Total active connections |
| `external_conns` | Filtered network_connections | Connections to non-RFC1918 IPs |
| `net_drift_%` | `last_diagnostics.network_baseline_drift` | Network baseline deviation % |
| `proc_drift_%` | `last_diagnostics.process_baseline_drift` | Process baseline deviation % |
| `processes` | `last_diagnostics.active_processes` | Count of active processes |
| `listening_ports` | Filtered LISTEN state connections | Listening port count |

### Anomaly Detection Rules

| Rule | Threshold | Event Topic |
|---|---|---|
| Critical threat score | score ≥ 70 | `ai.anomaly.critical_score` |
| Elevated threat score | score ≥ 40 | `ai.anomaly.elevated_score` |
| Network baseline drift | drift > 30% | `ai.anomaly.network_drift` |
| Process baseline drift | drift > 40% | `ai.anomaly.process_drift` |
| Metric spike | value > 2.5× rolling avg AND value > 10 | `ai.spike.<metric>` |

### State Object (`_ai_state`)

The monitor stores all live state in a dict on the `Dashboard` instance:

```python
{
    "metrics": {
        "threat_score": [float, ...],     # last 100 values
        "connections": [int, ...],
        "external_conns": [int, ...],
        "net_drift_%": [float, ...],
        "proc_drift_%": [float, ...],
        "processes": [int, ...],
        "listening_ports": [int, ...],
    },
    "anomaly_count": int,         # total anomaly events since start
    "assessment_count": int,      # total tick-agent pairs processed
    "latest_score": float,        # highest threat score seen
    "ai_events": [dict, ...],     # newest-first, capped at 500
    "last_tick": str,             # ISO timestamp of last cycle
    "uptime_cycles": int,         # total ticks since start
    "agents_monitored": int,      # agents with valid diagnostics last tick
    "status": str,                # "active" | "starting"
}
```

---

## SSE Live Stream (`/api/ai/live`)

The AI Engine page receives real-time push updates via **Server-Sent Events** (SSE). This is a persistent HTTP connection where the server pushes `data:` frames to the browser.

### Protocol

```
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no

data: {"metrics":{...},"anomaly_count":5,...}\n\n

: ping\n\n

data: {"metrics":{...},...}\n\n
```

### Timing

| Event | Interval |
|---|---|
| `data:` frame with full state | Every 5 seconds |
| `: ping` keepalive comment | Every 25 seconds |

The 25-second keepalive prevents Heroku's 55-second idle connection timeout from closing the stream.

### Browser Client

The AI Engine page connects using the native `EventSource` API:

```javascript
const sse = new EventSource('/api/ai/live');
sse.onmessage = (ev) => applyData(JSON.parse(ev.data));
sse.onerror = () => {
    // Exponential back-off: 5s → 10s → 20s → 30s cap
    setTimeout(reconnect, Math.min(5000 * Math.pow(2, fails - 1), 30000));
};
```

If SSE fails (e.g. network interruption), the page falls back to a single HTTP poll of `/api/ai/metrics` while waiting to reconnect.

---

## ML Models

All models are implemented in pure Python with zero external dependencies.

### Isolation Forest (`network_guardian/ai/anomaly.py`)

Reference: Liu, Ting & Zhou (2008) — "Isolation Forest"

**How it works:**
- Builds `n_trees` random isolation trees on training data
- Anomaly score = normalized average path length to isolate a sample
- Short path = easy to isolate = anomaly

**Initialization:**
```python
IsolationForest(
    n_trees=100,       # Number of isolation trees
    max_samples=256,   # Samples per tree
    threshold=0.6,     # Score ≥ 0.6 = anomaly
    seed=None          # Random seed for reproducibility
)
```

**Key methods:**
- `fit(data: list[list[float]]) → None` — Train on normal data
- `score(sample: list[float]) → AnomalyScore` — Score a single sample
- `score_batch(samples) → list[AnomalyScore]` — Batch scoring

**`AnomalyScore`:**
```python
{
    "score": 0.73,        # 0.0 = normal, 1.0 = highly anomalous
    "is_anomaly": True,   # score >= threshold
    "method": "isolation_forest",
    "details": {...}
}
```

---

### One-Class SVM (`network_guardian/ai/anomaly.py`)

Simplified RBF kernel density estimator for one-class classification.

**How it works:**
- Stores up to `max_support` training samples as support vectors
- Scores new samples by average RBF similarity to support vectors
- Low similarity = far from training distribution = anomaly

**RBF Kernel:**

$$k(a, b) = e^{-\gamma \cdot ||a - b||^2}$$

**Initialization:**
```python
OneClassSVM(
    gamma=None,        # RBF parameter (default: 1/n_features)
    nu=0.1,            # Expected fraction of anomalies in training data
    max_support=500,   # Maximum support vectors stored
    seed=None
)
```

**Threshold:** Set at the `nu`-quantile of training scores during `fit()`.

---

### ARIMA Forecaster (`network_guardian/ai/forecasting.py`)

Auto-Regressive Integrated Moving Average for time-series prediction.

**Configuration:** `ARIMA(p=3, d=1, q=1)` by default

| Parameter | Meaning |
|---|---|
| `p` | AR order — how many past values to use |
| `d` | Differencing order — how many times to difference for stationarity |
| `q` | MA order — how many past error terms to use |

**Methods:**
- `fit(series: list[float]) → dict` — Returns `{"mae", "rmse", "ar_coefficients"}`
- `predict(steps: int, confidence=0.95) → ForecastResult` — Forecast `steps` ahead with confidence intervals

**`ForecastResult`:**
```python
{
    "method": "arima",
    "points": [
        {"step": 1, "value": 12.3, "lower": 10.1, "upper": 14.5},
        ...
    ],
    "metrics": {"mae": 0.8, "rmse": 1.1}
}
```

---

### Holt-Winters Forecaster (`network_guardian/ai/forecasting.py`)

Exponential smoothing with trend and seasonal components.

- Handles both additive and multiplicative seasonality
- Suitable for network metrics with daily/weekly patterns
- Zero external dependencies

---

## AI Node Graph (`network_guardian/ai/nodes.py`)

ROS-inspired compute graph where ML models are nodes and data flows between them as typed messages. Nodes can be composed into pipelines.

```
SensorNode → PreprocessNode → AnomalyNode → ThresholdNode → AlertNode
```

---

## NLP Engine (`network_guardian/ai/nlp.py`)

Parses command inputs and log lines using rule-based NLP:

- Extract IP addresses, port numbers, hostnames from free text
- Classify intent (scan, block, audit, monitor, etc.)
- Powers the remote control command interface (WhatsApp/SMS/etc.)

---

## AI Engine Dashboard Page (`/ai`)

The AI Engine page displays:

| Panel | Description |
|---|---|
| **KPI Bar** | Anomaly count, prediction count, metric count, AI event count |
| **Status Bar** | Monitor status (ACTIVE), agents monitored, cycle count, last update time |
| **Anomaly Timeline** | Canvas chart — 60-point rolling threat score history with anomaly threshold line |
| **System Metrics** | Canvas chart — multi-line time-series for all 7 metrics (last 20 points each) |
| **Metric Values** | Current value + rolling average for each metric |
| **AI Events** | Real-time event feed — topic, timestamp, detail (newest first, 30 shown) |
| **Model Cards** | Status cards for: Isolation Forest, One-Class SVM, Ensemble, ARIMA, Holt-Winters, NLP |

### Live Update Mechanism

```
Page Load
    │
    ├─► HTTP GET /api/ai/metrics  (initial data fill)
    │
    └─► EventSource /api/ai/live  (persistent SSE stream)
              │
              ├─► data: event every 5s  →  applyData()
              │                              ├── update KPI counters
              │                              ├── push to aHist[]
              │                              ├── drawAnom() canvas
              │                              ├── drawMet() canvas
              │                              ├── render metric list
              │                              └── render events list
              │
              └─► error → exponential backoff → reconnect
                          + one HTTP poll to /api/ai/metrics
```

---

## Smart Automation (`network_guardian/ai/smart_automation.py`)

The `SmartAutomation` module uses the trained models to automatically:

- Trigger IPS blocks based on anomaly score thresholds
- Adjust scan intervals based on detected risk level
- Escalate alerts when multiple models agree on an anomaly
- Generate automated remediation task suggestions
