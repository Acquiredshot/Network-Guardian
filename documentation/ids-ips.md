# IDS / IPS

---

## Intrusion Detection System (IDS)

### Overview

The IDS (`network_guardian/ids/__init__.py`) combines signature-based detection, anomaly detection, heuristic analysis, and multi-stage attack correlation. It fires `ids.alert` events onto the EventBus, which the IPS subscribes to for automated response.

### Starting

```python
await engine.ids.start()   # Starts detection loop
await engine.ids.stop()    # Graceful shutdown
```

Or via dashboard control: POST `/api/control/ids/start`

---

### Threat Categories

```python
class ThreatCategory(Enum):
    PORT_SCAN            = "port_scan"
    BRUTE_FORCE          = "brute_force"
    DOS                  = "dos"
    MALWARE              = "malware"
    DATA_EXFIL           = "data_exfil"
    INJECTION            = "injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT     = "lateral_movement"
    C2_COMMUNICATION     = "c2_communication"
    POLICY_VIOLATION     = "policy_violation"
    RECONNAISSANCE       = "reconnaissance"
    UNKNOWN              = "unknown"
```

### Detection Methods

```python
class DetectionMethod(Enum):
    SIGNATURE   = "signature"    # Regex pattern matching (Snort-style)
    ANOMALY     = "anomaly"      # Statistical deviation
    HEURISTIC   = "heuristic"    # Rule-based behavioral analysis
    CORRELATION = "correlation"  # Multi-stage attack chains
```

### Signature Rules

Each rule is a `SignatureRule` with a compiled regex pattern:

```python
@dataclass
class SignatureRule:
    sid: int                # Unique rule ID
    name: str               # Human-readable name
    pattern: str            # Regex pattern
    category: ThreatCategory
    severity: Severity      # info, low, medium, high, critical
    description: str
    enabled: bool = True
```

**Default Rules by Category:**

| SID Range | Category | Examples |
|---|---|---|
| 1001–1003 | Reconnaissance | TCP SYN Scan, ICMP Sweep, Service Enumeration |
| 2001–2002 | Brute Force | SSH Brute Force, Login Brute Force |
| 3001–3003 | Injection | SQL Injection, Command Injection, XSS |
| 4001 | DoS | SYN Flood |
| 5001+ | Malware/C2 | Known malware signatures, C2 beacon patterns |

Total default rules: **37**

### Alert Model

```python
@dataclass
class Alert:
    alert_id: str           # UUID
    rule_name: str
    category: ThreatCategory
    severity: Severity
    source_ip: str
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    method: DetectionMethod = SIGNATURE
    description: str = ""
    raw_data: str = ""
    timestamp: datetime
    metadata: dict[str, Any]
```

`alert.as_dict` → serializable dict for API/storage.

### Alert Suppression

- Identical alerts (same rule + same source IP) are suppressed during the cooldown window
- Default cooldown: `MonitorConfig.alert_cooldown = 300` seconds (5 minutes)
- Prevents alert storms from repeated port scans or brute-force attacks

### Multi-Stage Correlation

The IDS correlates sequences of alerts to detect complex attack chains:

| Correlation Pattern | Example |
|---|---|
| Recon → Exploitation | Port scan followed by injection attempt from same IP |
| Lateral Movement chain | Multiple internal hosts compromised in sequence |
| Brute Force → Success | Failed logins followed by privileged action |

Correlation events fire `ids.correlation` on the EventBus.

---

## Intrusion Prevention System (IPS)

### Overview

The IPS (`network_guardian/ips/__init__.py`) automatically responds to IDS alerts by blocking, rate-limiting, or quarantining offending IPs. It can also be controlled manually via the dashboard or remote control commands.

### Starting

```python
await engine.ips.start()   # Start IPS response loop
await engine.ips.stop()
```

---

### Response Actions

```python
class ResponseAction(Enum):
    BLOCK       = "block"        # Drop all traffic
    RATE_LIMIT  = "rate_limit"   # Token-bucket throttle
    QUARANTINE  = "quarantine"   # Isolate to restricted zone
    ALERT_ONLY  = "alert_only"   # Log but take no action
    DROP        = "drop"         # Silently drop packets
    RESET       = "reset"        # Send TCP RST
```

### Block Reasons

```python
class BlockReason(Enum):
    AUTO_IDS     = "auto_ids"      # Triggered by IDS alert
    MANUAL       = "manual"        # Operator-initiated
    RATE_EXCEEDED = "rate_exceeded" # Token bucket exhausted
    BRUTE_FORCE  = "brute_force"   # Authentication brute force
    POLICY       = "policy"        # Policy violation
```

---

### Default Response Policy

The IPS maps each `ThreatCategory` to a `(ResponseAction, duration_seconds)` tuple:

| Threat Category | Action | Duration |
|---|---|---|
| `PORT_SCAN` | `RATE_LIMIT` | 300s (5 min) |
| `BRUTE_FORCE` | `BLOCK` | 1800s (30 min) |
| `DOS` | `BLOCK` | 600s (10 min) |
| `MALWARE` | `BLOCK` | **Permanent** |
| `DATA_EXFIL` | `BLOCK` | 3600s (1 hour) |
| `INJECTION` | `BLOCK` | 3600s (1 hour) |
| `PRIVILEGE_ESCALATION` | `BLOCK` | 1800s (30 min) |
| `LATERAL_MOVEMENT` | `QUARANTINE` | **Permanent** |
| `C2_COMMUNICATION` | `BLOCK` | **Permanent** |
| `POLICY_VIOLATION` | `ALERT_ONLY` | — |
| `RECONNAISSANCE` | `ALERT_ONLY` | — |
| `UNKNOWN` | `ALERT_ONLY` | — |

Duration `0` = permanent (never expires).

---

### Block Entry Model

```python
@dataclass
class BlockEntry:
    ip: str
    reason: BlockReason
    action: ResponseAction
    severity: Severity
    created: datetime
    expires_at: float | None   # monotonic time; None = permanent
    alert_id: str = ""
    description: str = ""
    hit_count: int = 0         # incremented on each blocked packet attempt

    @property is_expired → bool
```

---

### Rate Limiting Model

Token-bucket algorithm per IP:

```python
@dataclass
class RateLimitEntry:
    ip: str
    max_requests_per_second: float = 1.0
    burst_size: int = 5
    tokens: float = 5.0        # Current token count
    last_refill: float         # Monotonic timestamp
    expires_at: float | None

    def allow() → bool         # True if request allowed (consumes 1 token)
```

Tokens refill at `max_requests_per_second` per second up to `burst_size`.

---

### IPS Events

Every action taken is logged as an `IPSEvent`:

```python
@dataclass
class IPSEvent:
    event_id: str
    action: ResponseAction
    target_ip: str
    reason: str
    severity: Severity
    alert_id: str = ""
    timestamp: datetime
```

---

### Allow List

The IPS maintains an allow list of IPs that are **never** blocked:

**Default allow list:**
- `127.0.0.1` (IPv4 loopback)
- `::1` (IPv6 loopback)

Operators can add IPs via the dashboard IPS page or via the control API.

---

### IPS API Operations

| Operation | Method |
|---|---|
| `is_blocked(ip)` | Check if IP is currently blocked |
| `block(ip, duration)` | Manually block an IP |
| `remove_from_blocklist(ip)` | Unblock an IP |
| `rate_limit(ip, max_rps)` | Apply rate limit |
| `quarantine(ip)` | Quarantine an IP |
| `get_blocklist()` | All active block entries |
| `add_to_allowlist(ip)` | Permanently whitelist an IP |
| `get_history()` | All IPS events |

---

### Event Bus Integration

```
IDS fires: ids.alert  →  IPS auto_respond()
                              │
                              ├── Look up policy for threat category
                              ├── Check allow list
                              ├── Create BlockEntry / RateLimitEntry
                              └── Fire: ips.block | ips.rate_limit | ips.quarantine
                                            │
                                            └── Dashboard captures → live feed
```

---

## IP Cloaking System

The cloaking system (`network_guardian/cloaking/`) provides MAC masking, IP obfuscation, source rotation, and identity management for agent traffic.

### CloakingAgent ReAct Loop

The `CloakingAgent` (`network_guardian/cloaking/react_agent.py`) runs its own Observe → Reason → Act → Learn cycle to adapt cloaking strategy based on network environment:

| Network Type | Recommended Strategy |
|---|---|
| `public` | Full cloaking (MAC + IP + Tor + jitter) |
| `hotspot` | Full cloaking |
| `corporate` | Moderate (no MAC rotation, use proxy) |
| `home` | Minimal (timing jitter only) |
| `unknown` | Full cloaking |

### Network Profiling

The agent builds persistent profiles per network fingerprint (`{gateway_ip}\|{public_ip}`):

```python
NetworkProfile:
    fingerprint: str
    network_type: str        # hotspot, home, corporate, public, unknown
    first_seen: str
    last_seen: str
    times_connected: int
    avg_gateway_latency: float
    avg_internet_latency: float
    recommended_mode: str    # "full", "moderate", "minimal"
    threat_score: float      # 0.0 (safe) → 1.0 (hostile)
    notes: list[str]
```

Threat score increases when:
- Latency anomalies detected (possible MITM/proxy interception)
- Unknown hops appear in traceroute
- DNS servers changed unexpectedly
- Public IP changes without network change
