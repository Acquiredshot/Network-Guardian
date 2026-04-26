# API Reference

All endpoints are served by the async HTTP dashboard server. All API endpoints require session authentication (via `ng_session` cookie) unless noted. All POST endpoints require `Content-Type: application/json` and `X-Requested-With: XMLHttpRequest`.

---

## Authentication

### POST `/api/auth/login`
Authenticate with Wolfpak credentials and receive a session cookie.

**Auth required:** No

**Request:**
```json
{ "username": "admin", "password": "<password>" }
```

**Response:**
```json
{ "ok": true, "message": "Authenticated", "role": "admin" }
```

**On failure:** `{ "ok": false, "message": "Invalid credentials" }`

**Sets cookie:** `ng_session=<signed-token>; HttpOnly; SameSite=Strict; Secure` (Secure added on HTTPS)

---

### POST `/api/auth/change-password`
Change the authenticated user's password.

**Auth required:** Yes (session cookie)

**Request:**
```json
{ "current_password": "...", "new_password": "..." }
```

**Password policy:** 8+ chars, uppercase, digit, special char.

**Response:** `{ "ok": true, "message": "Password updated" }`

---

## Team Management

All `/api/team/` endpoints require **admin role**.

### GET `/api/team/list`
List all team members (no password hashes).

**Response:**
```json
[
  {
    "username": "admin",
    "display_name": "Admin",
    "role": "admin",
    "active": true,
    "created_at": 1745000000,
    "password_set_at": 1745000000,
    "days_until_expiry": 45,
    "expired": false
  }
]
```

---

### POST `/api/team/add`
Add a new team member.

**Request:**
```json
{ "username": "C.Curry", "password": "P@kTerr1tory", "role": "operator" }
```

**Roles:** `admin`, `operator`, `viewer`

**Response:** `{ "ok": true, "message": "Member added" }`

---

### POST `/api/team/remove`
Remove a team member.

**Request:** `{ "username": "C.Curry" }`

**Response:** `{ "ok": true, "message": "Member removed" }`

---

### POST `/api/team/reset-password`
Reset a member's password (admin) or your own (any role).

**Request:**
```json
{ "username": "C.Curry", "new_password": "NewP@ss1word" }
```

**Response:** `{ "ok": true, "message": "Password reset" }`

---

## Fleet Agents

### POST `/api/fleet/register`
Register a new field agent. Called automatically by the probe on first run.

**Auth required:** HMAC signature (`X-Agent-Signature` header)

**Request:** Agent identity JSON (see [fleet-agents.md](fleet-agents.md))

**Response:** `{ "ok": true, "agent_id": "NG-XXXX" }`

---

### POST `/api/fleet/auth`
Authenticate a field agent (Wolfpak credentials gate).

**Auth required:** HMAC signature

**Request:** `{ "username": "...", "password": "..." }`

**Response:**
```json
{ "ok": true, "operator": "admin", "agent_token": "...", "role": "admin" }
```

---

### POST `/api/fleet/report`
Submit a full agent report (WiFi, hosts, metrics, threats).

**Auth required:** HMAC signature (`X-Agent-Signature: <hmac-sha256>`)

**Max body:** 256 KB

**Request:** `AgentReport` JSON (see [fleet-agents.md](fleet-agents.md))

**Response:** `{ "ok": true }`

---

### GET `/api/fleet/key`
Retrieve the raw fleet HMAC key.

**Auth required:** Session + **admin role**

**Response:** `{ "fleet_key": "eNyg..." }`

**Non-admin returns:** HTTP 403

---

### GET `/api/fleet/list`
List all registered agents with their last-seen status.

**Response:**
```json
{
  "agents": {
    "NG-XXXX": {
      "hostname": "...",
      "platform": "darwin",
      "last_seen": 1745000000,
      "threat_count": 2
    }
  }
}
```

---

### GET `/api/fleet/threats`
All threat alerts from all agents, newest first.

**Response:** `[ { "agent_id": "NG-XXXX", "threat_type": "...", "severity": "high", ... } ]`

---

### GET `/api/fleet/reports`
All `ThreatReport` structured assessment documents from all agents.

---

### GET `/api/fleet/incidents`
All Markdown incident reports from all agents.

---

### GET `/api/fleet/agent/<agent_id>`
Full details for a single agent.

---

### GET `/api/fleet/agent/<agent_id>/diagnostics`
Latest diagnostics snapshot for an agent.

---

### GET `/api/fleet/agent/<agent_id>/threats`
Threat history for a single agent.

---

### GET `/api/fleet/agent/<agent_id>/reports`
`ThreatReport` documents for a single agent.

---

### GET `/api/fleet/agent/<agent_id>/incidents`
Markdown incident reports for a single agent.

---

### GET `/api/fleet/agent/<agent_id>/sentinel`
Latest sentinel `NetworkDigest` for an agent.

---

## AI Engine

### GET `/api/ai/metrics`
Current AI monitoring state: rolling time-series, anomaly counts, latest score, recent AI events.

**Response:**
```json
{
  "status": "active",
  "latest_score": 12.4,
  "anomaly_count": 3,
  "assessment_count": 47,
  "uptime_cycles": 120,
  "agents_monitored": 2,
  "last_tick": 1745000000,
  "series": {
    "threat_score": [0, 5, 12, ...],
    "connections": [40, 42, 45, ...],
    "external_conns": [8, 9, 8, ...],
    "net_drift_%": [0, 1.2, 0.5, ...],
    "proc_drift_%": [0, 0, 2.1, ...],
    "processes": [120, 122, 121, ...],
    "listening_ports": [14, 14, 15, ...]
  },
  "ai_events": [ ... ]
}
```

---

### GET `/api/ai/live`
**Server-Sent Events (SSE)** stream of real-time AI monitor events.

**Content-Type:** `text/event-stream`

Events are emitted on each 10-second monitor tick and whenever an anomaly is detected. A `: ping` keepalive is sent every 25 seconds.

**Event format:**
```
data: {"type": "ai.tick", "score": 12.4, "anomaly": false, "timestamp": ...}

data: {"type": "ai.anomaly_detected", "severity": "elevated", "message": "...", ...}
```

---

## IPS

### GET `/api/ips/stats`
IPS runtime statistics (packets inspected, blocks, rate limits).

### GET `/api/ips/blocklist`
Current active block entries.

### GET `/api/ips/ratelimits`
IPs currently rate-limited.

### GET `/api/ips/quarantine`
Active quarantine zones.

### GET `/api/ips/history`
Block/unblock history (last N events).

### GET `/api/ips/allowlist`
Permanent allow list entries.

---

## IDS

### GET `/api/ids/stats`
IDS runtime counters (rules loaded, alerts fired, correlations).

### GET `/api/ids/alerts`
Recent IDS alerts (last 50), newest first.

### GET `/api/ids/rules`
All loaded signature rules.

---

## WiFi

### GET `/api/wifi/networks`
All WiFi networks visible to the local agent or the most recent fleet agent report.

**Response:**
```json
[
  {
    "ssid": "HomeNet",
    "bssid": "aa:bb:cc:dd:ee:ff",
    "signal": -65,
    "channel": 6,
    "frequency": "2.4 GHz",
    "security": "WPA2",
    "hidden": false,
    "connected": true
  }
]
```

### GET `/api/wifi/status`
Summary: connected SSID, signal strength, rogue AP count.

---

## Cloaking

### GET `/api/cloaking/status`
Active identity, rotation schedule, proxy status.

### GET `/api/cloaking/react`
Latest cloaking ReAct agent state.

### GET `/api/cloaking/networks`
Learned network profiles.

---

## Explorer

### GET `/api/explorer/topology`
Network topology map: discovered hosts, open ports, OS guesses.

---

## Control

### POST `/api/control/<action>`
Trigger engine control actions (start subsystem, run scan, etc.). Admin only.

---

## Wolfpak Store

### GET `/api/wolfpak/clients`
Connected Wolfpak clients (WolfPak store integration).

---

## General

### GET `/api/status`
Engine running state and subsystem availability.

**Response:**
```json
{
  "engine_running": true,
  "subsystems": {
    "auditor": true,
    "monitor": true,
    "explorer": true,
    "automator": true
  }
}
```

### GET `/api/events`
Last 50 live events from all subscribed engine topics.

### GET `/api/hosts`
Discovered hosts (from local explorer or aggregated fleet data).

### GET `/api/tasks`
Registered automator tasks and execution history.

### GET `/api/health`
Liveness probe. Always returns `{ "status": "ok" }` if the server is up.

---

## Common Response Codes

| Code | Meaning |
|---|---|
| `200` | OK |
| `400` | Bad request (malformed JSON) |
| `401` | Not authenticated |
| `403` | Forbidden (wrong role) |
| `404` | Route not found |
| `405` | Method not allowed |
| `413` | Payload too large (>4 KB for most routes, >256 KB for fleet reports) |
| `415` | Content-Type not `application/json` |
| `429` | Rate limit exceeded |
| `431` | Request headers too large (>8 KB) |

## CSRF Protection

All POST endpoints require the `X-Requested-With: XMLHttpRequest` header. Requests without this header receive HTTP 403. This blocks cross-origin form-based POST attacks.
