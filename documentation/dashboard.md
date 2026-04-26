# Dashboard

The dashboard is a zero-dependency async HTTP server implemented with `asyncio.start_server`. No ASGI framework, no Flask, no FastAPI — pure Python sockets with an asyncio event loop.

---

## Architecture

```python
class Dashboard:
    engine: Engine          # Core engine reference
    host: str               # Bind address
    port: int               # HTTP port (default 8080, env PORT on Heroku)
    _fleet: FleetStore      # Agent registry
    _team: TeamStore        # User accounts
    _wolfpak: WolfpakClientStore
    _cloak_agent: CloakingAgent
    _recent_events: list[dict]   # Live event feed (last 200)
    _ai_state: dict              # 24/7 AI monitor state
    _ai_monitor_task: Task       # Background asyncio task
```

### Lifecycle

```python
await dashboard.start()   # Binds port, creates AI monitor task
await dashboard.stop()    # Cancels monitor task, closes server
```

---

## Pages

| Route | Page | Description |
|---|---|---|
| `/` | Dashboard | Fleet map canvas, KPI bar, live event feed, findings |
| `/ids` | IDS | Alert log, rule hits, correlation events |
| `/ips` | IPS | Block list, rate-limit table, quarantine zones, allow list |
| `/wifi` | WiFi | Connected networks, rogue AP alerts, SSID history |
| `/cloaking` | Cloaking | Active identity, proxy status, learned network profiles |
| `/explorer` | Explorer | Network topology, host discovery |
| `/auditor` | Auditor | Compliance findings |
| `/ai` | AI Engine | 24/7 time-series charts, anomaly detection, AI event stream |
| `/fleet` | Fleet | All registered agents, per-agent drill-down |
| `/reports` | Reports | Filterable threat assessment cards |
| `/incidents` | Incidents | Markdown incident reports with download |
| `/login` | Login | Authentication page |

---

## Authentication

### Session Authentication

All pages (except `/login`) require a valid session cookie. Sessions are HMAC-signed using a server secret generated on startup via `secrets.token_urlsafe()`.

**Login flow:**
1. POST to `/api/auth/login` with `{"username": "...", "password": "..."}`
2. Server validates against `TeamStore`
3. On success: returns `Set-Cookie: ng_session=<signed-token>`
4. All subsequent requests include the cookie

**Brute-force protection:**
- Tracks failed login attempts per IP address
- Exponential back-off applied after repeated failures
- Max attempts configurable via `SecurityConfig.max_login_attempts` (default: 5)

**Secure cookie (HTTPS):**
The `ng_session` cookie is set with `; Secure` automatically when the request arrives over HTTPS (`X-Forwarded-Proto: https`). This is active on Heroku by default and prevents the session cookie from being sent over plain HTTP connections.

### Fleet Agent Authentication

Fleet agent endpoints (`/api/fleet/report`, `/api/fleet/register`, `/api/fleet/auth`) bypass session auth and use HMAC-SHA256 with the fleet key instead.

Request header: `X-Fleet-Key: <hmac-sha256-signature>`

### Fleet Key API (`/api/fleet/key`)

The raw fleet HMAC key is accessible via `GET /api/fleet/key`. **This endpoint requires the `admin` role** — operator and viewer accounts receive HTTP 403. This prevents any authenticated non-admin from extracting the fleet key and forging agent reports.

---

## Team Management

User accounts are managed via `TeamStore` (`~/.network_guardian/wolfpak_team.json`).

### Roles

| Role | Capabilities |
|---|---|
| `admin` | Full access: read, execute, team management |
| `operator` | Read + execute (no team management) |
| `viewer` | Read-only |

### Default Account

On first boot with no team members, a default admin account is created:

- **Username:** `admin`
- **Password:** `<password>`
- ⚠️ Change this immediately after first login

### Team API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/team/list` | GET | List all team members |
| `/api/team/add` | POST | Add team member (admin only) |
| `/api/team/remove` | POST | Remove team member (admin only) |
| `/api/team/reset-password` | POST | Reset member password (admin only) |

All `/api/team/` endpoints require the `admin` role. Operators and viewers receive HTTP 403.

### Password Policy

Passwords must satisfy all of the following when set or changed:

| Rule | Requirement |
|---|---|
| Minimum length | 8 characters |
| Uppercase letter | At least one `A–Z` |
| Digit | At least one `0–9` |
| Special character | At least one of `!@#$%^&*()_+-=[]{}|;':,./<>?` |

Passwords expire after **60 days** (`PASSWORD_MAX_AGE`). Expired passwords must be changed on next login.

---

## Rate Limiting

All API endpoints are protected by a per-IP token bucket rate limiter tracked in `_rate_tracker: dict[str, list[float]]`.

- Burst allowed for legitimate users
- Automatic back-off for clients exceeding limits
- Returns HTTP 429 when limit exceeded

---

## Live Event Feed

The dashboard subscribes to engine events on startup:

```python
SUBSCRIBED_TOPICS = [
    "audit.finding", "monitor.anomaly", "ai.anomaly_detected",
    "explorer.discovery_complete", "automator.task_complete",
    "ips.block", "ips.unblock", "ips.rate_limit",
    "ips.quarantine", "ips.quarantine_release", "ips.started",
    "ids.alert", "ids.started", "ids.correlation",
]
```

Events are stored in `_recent_events` (last 200) and exposed via `/api/events`.

---

## Content Security Policy

A fresh CSP nonce (`secrets.token_urlsafe(16)`) is generated on each server start and injected into all inline `<script>` and `<style>` tags via the `{{NONCE}}` template placeholder.

---

## Dashboard Page — Detail

### `/` — Main Dashboard

- **Fleet Map** — Canvas animation showing agent nodes and their health status
- **KPI Bar** — Active agents, threats detected, IDS alerts, blocked IPs
- **Event Feed** — Rolling live events from all subscribed topics
- **Findings** — Latest audit findings from the Auditor subsystem

### `/ids` — IDS

- Alert log with severity badges, rule name, source IP, description
- Auto-refreshes every 3 seconds
- Timestamp column with locale-formatted time

### `/ips` — IPS

- Active block list table (IP, action, reason, expiry)
- Rate-limited IPs table
- Quarantine zone list
- Allow list management
- Auto-refreshes every 3 seconds

### `/wifi` — WiFi

- Detected networks with signal strength bars, security badge, frequency
- Color-coded security: WPA3 (green), WPA2 (blue), WEP (orange), Open (red)
- Rogue AP alerts with risk level
- Connected network details

### `/cloaking` — Cloaking

- Current active identity (MAC, IP, hostname)
- Proxy chain status
- Timing jitter status
- Learned network profiles from CloakingAgent
- Network type classification (home, corporate, public, hotspot)

### `/ai` — AI Engine

See [ai-engine.md](ai-engine.md) for full details.

### `/fleet` — Fleet

- Agent table: ID, hostname, OS, status, last seen, threat score, risk level
- Per-agent drill-down:
  - Live diagnostics
  - Threat history timeline
  - Detailed threat reports
  - Incident reports
  - Sentinel bot data (WiFi changes, flow anomalies, rogue APs)

### `/reports` — Reports

- Filterable card view of all threat assessment reports
- Filter by: severity level, risk category, agent
- Each card expandable to show:
  - Full threat list with CVSS scores
  - Observations (connections, processes, ports)
  - Recommendations

### `/incidents` — Incidents

- List of all generated Markdown incident reports
- Inline rendered Markdown preview
- `.md` download button for each report
- Reports generated automatically on every threat detection

---

## Wolfpak Admin Client Registry

Wolfpak admin clients (the `wolfpak/` package — phone/tablet admin apps) register themselves with the dashboard via HTTP headers on any authenticated request:

```
X-WP-Tag: wolfpak-ios
X-WP-Client: iPhone-14-Pro
X-WP-Host: 192.168.1.50
```

The `WolfpakClientStore` tracks all such connections and exposes them at `/api/wolfpak/clients`.

---

## Controls

The dashboard exposes a control API at `/api/control/` for executing engine actions:

| Endpoint | Action |
|---|---|
| `/api/control/ids/start` | Start IDS |
| `/api/control/ids/stop` | Stop IDS |
| `/api/control/ips/block` | Block an IP |
| `/api/control/ips/unblock` | Unblock an IP |
| `/api/control/ips/quarantine` | Quarantine an IP |
| `/api/control/scan` | Trigger network scan |
| `/api/control/audit` | Trigger compliance audit |
