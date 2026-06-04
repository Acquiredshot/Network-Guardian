# Network Guardian — Patch & Recommendation Delivery System

## Overview

The patch delivery system provides centralized distribution of security recommendations, system hardening fixes, and vulnerability patches to remote probes and fleet agents. Each patch includes severity levels, CVE identifiers, and pre-built remediation commands ready for deployment.

---

## Capabilities

### Patch Distribution
- **Centralized Management** — Define patches once, deliver to all probes
- **Severity-Based Prioritization** — Critical, High, Medium, Low classifications
- **CVE Tracking** — Link patches to specific CVE identifiers
- **Auto-Generated Commands** — Ready-to-execute fix commands for each patch
- **Status Tracking** — Monitor which agents have applied which patches
- **Audit Trail** — Persistent record of all patch deployments

### Patch Types

| Type | Example | Severity |
|------|---------|----------|
| **Security Updates** | Update OpenSSL, disable TLS 1.0 | Critical |
| **Authentication Hardening** | Disable SSH password auth, enforce key-based | High |
| **Firewall Rules** | Enable UFW, restrict inbound ports | High |
| **Service Hardening** | Disable plaintext protocols (Telnet/FTP) | High |
| **System Packages** | OS security patches, kernel updates | Medium |
| **Auto-Update Configuration** | Enable automatic security updates | Medium |

---

## Usage

### Fetching Patches on a Probe

**Command:**
```bash
cd /path/to/Network\ Guardian
python3 fetch_patches.py [dashboard_url] [agent_id] [username] [password]
```

**Examples:**

Local dashboard:
```bash
python3 fetch_patches.py http://127.0.0.1:8080 NG-608852BB <username> <password>!
```

Centralized server:
```bash
python3 fetch_patches.py http://192.168.1.12:8081 NG-608852BB <username> <password>!
```

**Output:**
```
======================================================================
  RECOMMENDED PATCHES (6 available)
======================================================================

[CRITICAL] 1 patch(es)

  • Update OpenSSL to 1.1.1 or later
    Description: Critical: TLS 1.0 and TLS 1.1 vulnerabilities (CVE-2021-41117)
    CVE: CVE-2021-41117
    Fix command:
    $ brew upgrade openssl

[HIGH] 3 patch(es)

  • Disable SSH password authentication
    Description: High: SSH brute force exposure - enforce key-based auth only
    Fix command:
    $ sudo sed -i '' 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd
    
...

✓ Patches saved to: /Users/username/.network_guardian/patches/pending_patches.json
```

### Automating Patch Checks

Add to probe's heartbeat loop (every 30 seconds):
```python
subprocess.run([
    sys.executable, "fetch_patches.py",
    base_url, agent_id, username, password
])
```

Or schedule with cron:
```bash
*/30 * * * * cd /path/to/Network\ Guardian && python3 fetch_patches.py http://127.0.0.1:8080 NG-LOCAL <username> <password>! >> /tmp/patches.log 2>&1
```

---

## Patch Management API

### Fetch Patches
**Endpoint:** `GET /api/patches`

**Parameters:**
- `agent_id` (optional) — Filter patches for specific agent
- `limit` (optional) — Maximum patches to return (default: 20)

**Response:**
```json
{
  "status": "ok",
  "agent_id": "NG-608852BB",
  "patch_count": 6,
  "patches": [
    {
      "id": "PATCH-20260528180000",
      "title": "Update OpenSSL to 1.1.1 or later",
      "description": "Critical: TLS 1.0 and TLS 1.1 vulnerabilities (CVE-2021-41117)",
      "severity": "critical",
      "category": "cryptography",
      "cve_id": "CVE-2021-41117",
      "command": "brew upgrade openssl",
      "created_at": "2026-05-28T18:00:00Z",
      "status": "pending"
    }
  ]
}
```

### Report Patch Applied
**Endpoint:** `POST /api/patches/{patch_id}/apply`

**Body:**
```json
{
  "agent_id": "NG-608852BB"
}
```

**Response:**
```json
{
  "status": "applied",
  "patch_id": "PATCH-20260528180000",
  "agent_id": "NG-608852BB",
  "timestamp": "2026-05-28T18:30:00Z"
}
```

---

## Patch Storage

Patches are stored locally at:
```
~/.network_guardian/patches/
├── recommended_patches.json    # Master patch list
├── pending_patches.json        # Last fetched patches
└── applied_patches.json        # Deployment history (optional)
```

---

## Architecture

### Components

**`network_guardian/interface/patches_api.py`**
- `PatchStore` — Manages patch lifecycle (create, fetch, mark applied)
- `PatchesAPI` — Provides HTTP API endpoints for patch delivery

**`fetch_patches.py`**
- Command-line tool for probes to fetch patches
- Authenticates with dashboard or centralized server
- Displays patches grouped by severity
- Saves patch list locally for offline reference

**Integration Points**
- Dashboard exposes `/api/patches` endpoint
- Probes call `fetch_patches.py` on regular intervals
- Centralized server forwards patches to all connected clients

---

## Recent Patches Applied

| Date | Severity | Component | Description |
|------|----------|-----------|-------------|
| 2026-06-04 | LOW | `dashboard.py` — `loadStatus()` | Added 401 redirect guard to `/api/ransomware/status` poll — prevents unauthenticated request loop on session expiry |

---

## Patch Categories

| Category | Purpose | Examples |
|----------|---------|----------|
| **cryptography** | TLS/SSL, encryption updates | OpenSSL, certificate validation |
| **authentication** | Auth mechanism hardening | SSH key enforcement, MFA |
| **firewall** | Network access control | UFW, iptables, network zones |
| **network** | Network protocol security | Disable plaintext protocols |
| **updates** | System and package patches | OS, kernel, dependencies |
| **security** | General security fixes | Default fixes |

---

## Severity Levels

| Level | Action Required | Timeline | Examples |
|-------|-----------------|----------|----------|
| **CRITICAL** | Immediate | Within 24 hours | RCE, authentication bypass, data breach |
| **HIGH** | Urgent | Within 1 week | Privilege escalation, known exploits |
| **MEDIUM** | Important | Within 2 weeks | Defense improvement, config hardening |
| **LOW** | Recommended | Within 1 month | Best practices, performance |

---

## CVE Integration

Each patch can reference CVE identifiers:
```json
{
  "cve_id": "CVE-2021-41117",
  "title": "OpenSSL TLS 1.0/1.1 Vulnerability",
  "description": "Affected versions: < 1.1.1. Upgrade to 1.1.1j or later."
}
```

---

## Deployment Workflow

```
1. Dashboard/Operator creates patch
   ↓
2. Patch stored in ~/.network_guardian/patches/recommended_patches.json
   ↓
3. Probe calls fetch_patches.py (manual or scheduled)
   ↓
4. Probe displays available patches (grouped by severity)
   ↓
5. Administrator reviews and executes fix command
   ↓
6. Probe reports status via /api/patches/{patch_id}/apply
   ↓
7. Dashboard records successful deployment
```

---

## Troubleshooting

### Patches Not Fetching

**Check 1: Network connectivity**
```bash
curl -I http://127.0.0.1:8080/api/patches
# Should return HTTP 200 or 401 (if auth required)
```

**Check 2: Authentication**
```bash
python3 fetch_patches.py http://127.0.0.1:8080 NG-LOCAL <username> <invalid-password>
# Should display auth error, not 500
```

**Check 3: Probe permissions**
Ensure probe has write access to:
```bash
~/.network_guardian/patches/
```

### Patches Not Applying

1. **Verify command syntax** — Test command manually first
2. **Check OS compatibility** — Use platform-specific commands
3. **Validate permissions** — Some commands require sudo
4. **Review logs** — Check `/tmp/patches.log` for execution output

---

## Best Practices

✅ **DO:**
- Review patches before applying to production machines
- Test commands in isolated environment first
- Schedule patch checks during maintenance windows
- Maintain audit trail of applied patches
- Group related patches by theme

❌ **DON'T:**
- Apply untrusted patches from unknown sources
- Execute patches with `sudo` without review
- Skip critical security updates
- Automate patch execution without approval workflow
- Use plaintext credentials in scripts

---

## Future Enhancements

- [ ] Automated patch scheduling with approval workflow
- [ ] Patch rollback/downgrade capability
- [ ] Cross-team patch sharing and collaboration
- [ ] Patch testing sandbox before deployment
- [ ] Integration with CVE databases (NVD, CISA)
- [ ] Vulnerability assessment to recommend patches
- [ ] Patch effectiveness metrics and reporting
- [ ] UEBA-driven patch recommendations — surface targeted hardening fixes when a device's behavioral baseline flags persistent anomaly patterns

---

## Version History

### v35 — 2026-06-04

**UEBA: Per-Device Behavioral Baseline + Lateral Movement Detection**

- Added `DeviceBaselineManager` — per-IP rolling Isolation Forest baseline. Each device warms up independently (30 samples), then scores all future observations against its own personal model. Baselines persist across restarts under `~/.network_guardian/baselines/`.
- Added `LateralMovementDetector` — rolling 5-minute window fan-out tracker per source IP. Raises alerts when a device's unique destination count spikes ≥ 3σ above its historical baseline or crosses an absolute threshold of 20 destinations. History persists under `~/.network_guardian/lateral_movement.json`.
- Both detectors wired into the AI node graph as `DeviceBaselineNode` and `LateralMovementNode`; publish `ai.device_baseline_alert` and `ai.lateral_movement_alert` events to the engine bus.
- Engine exposes `engine.device_baseline_manager` and `engine.lateral_movement_detector` as lazy properties.
- 36 new tests added in `tests/test_ueba.py` — full suite now 591 passed, 0 failed.

### v34 — 2026-06-04

**Semantic Threat Detection: MCP Parser + Dual-Pass Evaluator + Isolation Sandbox**

- Added MCP/API Protocol Parser — semantic-layer threat detection for JSON-RPC 2.0, MCP, GraphQL, and multi-agent protocol streams.
- Added Dual-Pass Evaluation Pipeline — async pre/post verification workers that screen AI context before injection and after response generation.
- Added Isolation & Sandboxing Engine — per-session threat score aggregation with time-decay; severs TCP session and generates honeypot response on isolation.
- Full system expanded from 6 to 9 components in `run_full_system.py`.
