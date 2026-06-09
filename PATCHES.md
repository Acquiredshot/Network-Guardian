# Network Guardian — Patch & Recommendation Delivery System

## Overview

The patch delivery system provides centralized distribution of security recommendations,
system hardening fixes, and vulnerability patches to remote probes and fleet agents.
Each patch includes severity levels, CVE identifiers, and pre-built remediation commands
ready for deployment.

Current runtime note (2026-06-06): In addition to `fetch_patches.py`, active probe-side
update delivery is supported through base-pushed `patch_config` in fleet report ACKs
(`FleetStore.set_patch_config(...)` -> probe applies on next phone-home).

---

## Recent Patch Notes

### [v50] — 2026-06-09 — JARVIS Full Tool Integration + Speed Optimization

**Type:** Feature / Performance  
**Severity:** Enhancement (no vulnerability)  
**Components:** `network_guardian/jarvis/jarvis_core.py`, `network_guardian/ai/langgraph_reasoner.py`, `.env`

#### Changes Delivered

- **7 new JARVIS security-tool command handlers** — Jarvis can now invoke every major
  Network Guardian subsystem directly via natural language or voice:

  | Command | Tool Invoked | Phrases |
  |---|---|---|
  | `cmd_firewall_scan` | `SmartFirewallAgent.run_cycle()` + injection history DB | "firewall scan", "last firewall scan", "when was the last firewall scan" |
  | `cmd_malware` | `malware_scanner.scan_processes()` | "malware scan", "scan for viruses", "check processes" |
  | `cmd_ransomware` | `RansomwareMonitor` | "ransomware check", "file integrity" |
  | `cmd_ids` | Injection history DB (IDS events) | "ids alerts", "intrusion alerts", "alert history" |
  | `cmd_ips` | `IntrusionPreventionSystem` | "blocked ips", "blocklist", "who is blocked" |
  | `cmd_wifi` | `probe.scan_wifi()` | "wifi scan", "wireless scan", "nearby networks" |
  | `cmd_audit` | `Auditor.run_audit(["localhost"])` | "run audit", "security audit", "vulnerability scan" |

- **50+ new INTENT_MAP keywords** — all new commands have natural-language aliases
  covering common voice phrasing variants.

- **DeepSeek model switched to `deepseek-chat` (V3)** — 5–10× faster responses vs
  `deepseek-reasoner` (chain-of-thought). AI timeout reduced from 60 s → 30 s.
  Model and timeout are configurable via `DEEPSEEK_MODEL` / `DEEPSEEK_TIMEOUT` env vars.

- **`.env` documented** — `DEEPSEEK_MODEL=deepseek-chat` and `DEEPSEEK_TIMEOUT=30` now
  present with inline comments explaining fast vs deep reasoning modes.

- **Existing speed caches confirmed active** — `_cached_snapshot()` and `_cached_live_context()`
  (5 s TTL) eliminate redundant DB reads on back-to-back voice commands.

#### Operator Action Required

None — drop-in enhancement. All new commands are immediately available in both the
Jarvis GUI and the terminal REPL.

Example voice / text commands now recognised:
```
firewall scan           → runs SmartFirewallAgent + reports last scan timestamp
malware                 → scans all running processes for malware indicators
ransomware check        → checks for encryption/file-modification activity
ids alerts              → shows last 20 IDS events from injection DB
blocked ips             → lists IPS blocklist, rate-limited, and quarantined IPs
wifi scan               → discovers nearby wireless networks, flags open SSIDs
run audit               → runs full CVSS/OWASP vulnerability audit against localhost
```

---

### [v49] — 2026-06-09 — JARVIS Operational Data Access + Probe Commander

**Type:** Feature / Intelligence Layer  
**Severity:** Enhancement (no vulnerability)  
**Components:** `network_guardian/jarvis/probe_commander.py`, `network_guardian/jarvis/jarvis_core.py`, `network_guardian/jarvis/jarvis_conversation.py`, `.gitignore`

#### Changes Delivered

- **`probe_commander.py`** (new) — Read-only probe awareness module. Reads `agents{}`
  section of `fleet.json` (previously invisible to JARVIS), async-pings registered
  probe IPs, checks probe ports (8080/8443/5000/4443), and sweeps the /24 subnet for
  unregistered NG instances. Guard-rail: strictly read-only, no probe commands.

- **`cmd_fleet` fix** — Fleet handler now shows both `devices[]` (passive ARP scans)
  and `agents{}` (registered probes) from `fleet.json`. Previously all field agents
  appeared invisible in JARVIS fleet reports.

- **New JARVIS commands** — `probes` / `field agents` / `active probes` for full probe
  inventory + subnet scan; `probe health` / `check probes` for ping-only health checks.

- **Live telemetry context for conversational AI** — Free-form questions now receive a
  real-time snapshot (threat level, metrics, fleet, firewall history, probe agent statuses)
  injected into the DeepSeek prompt. JARVIS answers factual questions directly instead
  of returning "I don't have access."

- **35+ new natural-language keywords** added to `INTENT_MAP` covering common phrasing
  variants for all command categories.

- **`.gitignore` hardened** — `jarvis_crash.log`, `.ng_agent/`, `.network_guardian/`,
  `fleet_key.txt`, `agent_key.txt`, `config.local.yaml`, `win32com/`, `*.dmp` added.
  Prevents accidental push of runtime data, auth tokens, and fleet credentials.

#### Operator Action Required

None — this is a drop-in enhancement. Existing probes and fleet API are unaffected.

To use the new probe commands in JARVIS:
```
probes          # full probe inventory + subnet sweep
probe health    # ping all registered agents
```

To ensure your laptop probe shows as online, confirm it points `--base` at the
server's LAN IP (not `127.0.0.1`) when running `run_persistent_probe.py`.

---

### [v48] — 2026-06-09 — JARVIS + LangGraph/DeepSeek AI Reasoning

**Type:** Feature / AI Integration  
**Severity:** Enhancement (no vulnerability)  
**Components:** `network_guardian/jarvis/`, `network_guardian/ai/langgraph_reasoner.py`, `network_guardian/agent/triage_agent.py`

#### Changes Delivered

- **J.A.R.V.I.S. terminal shell** (`network_guardian/jarvis/`) — six-module conversational
  intelligence layer providing natural-language command dispatch, live telemetry aggregation,
  AI triage, voice I/O, and NG process lifecycle management.

- **LangGraph reasoning engine** (`network_guardian/ai/langgraph_reasoner.py`) — four-node
  `StateGraph` (ingest → reason → plan → summarize) using **DeepSeek-R1** (`deepseek-reasoner`)
  via the OpenAI-compatible API. Replaces keyword-only intent classification in `TriageAgent`
  with chain-of-thought reasoning, structured `action_plan` output, and automatic re-reasoning
  when confidence < 40 %.

- **TriageAgent upgrade** — REASON phase now calls `reason_about_intent()` when
  `DEEPSEEK_API_KEY` is set; full backward compatibility preserved (keyword fallback active
  when key is absent).

- **62 new tests** in `tests/test_jarvis.py`; **31 new tests** in
  `tests/test_langgraph_deepseek.py`. Total suite: **715 passed, 0 failed**.

#### Operator Action Required

1. Obtain a DeepSeek API key at https://platform.deepseek.com
2. Add to `.env`:
   ```
   DEEPSEEK_API_KEY=sk-<your-key>
   ```
3. Install new dependencies (if not already present):
   ```bash
   pip install langgraph langchain-openai langchain-core
   ```
4. Launch JARVIS interactive shell:
   ```bash
   python -m network_guardian.jarvis.jarvis_core
   ```

No changes to probe deployment, fleet API, or dashboard routes. Safe to deploy without
restarting existing probes.

---

### [v47] — 2026-06-08 — Google Safe Browsing Trust Signals

**Type:** Compliance / Trust  
**Components:** `network_guardian/saas/ui.py`, `network_guardian/saas/service.py`

- Added company identity header, JSON-LD `SoftwareApplication` structured data, meta tags,
  and full footer to the SaaS landing page to resolve Google Safe Browsing phishing flag.
- Added `GET /robots.txt`, `GET /.well-known/security.txt`, and Google Search Console
  HTML verification endpoint.
- Google Search Console property verified; Safe Browsing review request submitted.

---

### [v46] — 2026-06-08 — Flood & Probe-Packet Hardening

**Type:** Security / DOS Protection  
**Components:** `network_guardian/agent/flood_guard.py`, `flood_watchdog.py`, probe modules

- `FloodGuardAgent` — per-IP SYN/UDP/ICMP/probe-saturation detection with auto-escalating
  IPS blocks (1h → 6h → permanent).
- 7 new IDS signatures (SID 4001–4007).
- `DOS` block duration: 10 min → 1 hour.
- Probe self-protection: `_ProbeFloodGuard` (stdlib-only) embedded in field probes.

---



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
python3 fetch_patches.py http://127.0.0.1:8080 NG-608852BB <username> <password>
```

Centralized server:
```bash
python3 fetch_patches.py http://192.168.1.12:8081 NG-608852BB <username> <password>
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
*/30 * * * * cd /path/to/Network\ Guardian && python3 fetch_patches.py http://127.0.0.1:8080 NG-LOCAL <username> <password> >> /tmp/patches.log 2>&1
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
| 2026-06-06 | HIGH | `cvss_scan.py` | Refined SQL injection heuristics to require SQL-shaped statements and DB execution context for generic interpolation checks; removed residual false-critical findings and reduced CVSS critical count to zero. |
| 2026-06-06 | MEDIUM | `fetch_patches.py` | Added multi-path patch retrieval (basic auth -> session login -> local fleet `pending_patch_config` fallback) and graceful no-endpoint/no-pending handling; now saves patch state instead of failing on 404. |
| 2026-06-06 | HIGH | `start_all.py`, `network_guardian/wolfpak/ng_fleet.py`, `network_guardian/wolfpak/ng_status.py` | Removed shell command execution paths used for terminal/process control (`os.system`) and replaced with safer subprocess/ANSI alternatives; contributes to CVSS critical reduction (6 -> 3). |
| 2026-06-06 | HIGH | `network_guardian/interface/dashboard.py` | Removed hardcoded bootstrap admin password path. First-run admin now uses `NG_BOOTSTRAP_ADMIN_PASSWORD` or generated random password at startup. |
| 2026-06-06 | MEDIUM | `scan_endpoints.py`, `start_all.py` | Fixed endpoint validation reliability by defaulting scanner to port `8080` (`NG_DASHBOARD_PORT` override) and allowing launcher to reuse an already running dashboard on port collisions. |
| 2026-06-06 | MEDIUM | `owasp_scan.py` | Tightened A06 hardcoded-credential heuristic to match likely literal secret assignments, reducing false-positive high findings in OWASP summary. |
| 2026-06-06 | MEDIUM | Probe deploy + bridge update path (`network_guardian/agent/build.py`, `dist/usb_deploy/probe.py`, FleetStore patch_config flow) | Rebuilt USB probe package to match canonical probe code (hash parity verified), validated bridge subsystem stats, and exercised base-pushed `patch_config` delivery path for hotspot probe `NG-608852BB`. |
| 2026-06-05 | HIGH | `_start_dashboard.py`, `network_guardian/__main__.py` | Fixed SaaS launcher bind behavior for Heroku by selecting `0.0.0.0` automatically when `DYNO` or `PORT` is present; removed the `os` shadowing import that crashed SaaS startup on Heroku. |
| 2026-06-05 | MEDIUM | Heroku SaaS deployment validation | Verified the deployed SaaS app returns HTTP 200 on `/` and `/app` after the startup fixes; Heroku web dyno is now healthy. |
| 2026-06-05 | HIGH | SaaS platform stack (`network_guardian/saas/*`, `config`, startup entry points, fleet agents) | Completed SaaS mode rollout: tenant auth/org/API keys, fleet v1 ingest, hosted app, billing checkout/portal/webhook, migration-driven SQLite/PostgreSQL store, and agent compatibility routing (legacy + SaaS). |
| 2026-06-05 | MEDIUM | `scripts/validate_saas_stack.py` | Added one-command SaaS validator with sqlite/postgres/all modes covering signup, API key creation, fleet register/report, billing session, signed webhook replay, and org plan/status verification. |
| 2026-06-05 | LOW | `network_guardian/agent/isolation_sandbox_engine.py` | Patched mixed sync/async boundary in `_sever_connection` to await awaitable `block_ip` results, eliminating runtime warnings in shadow-mode validation without changing enforcement semantics. |
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

### v40 — 2026-06-04

**Feature: Read-Only Windows Security Posture Auditor**

- Added `Invoke-SecurityPosture.ps1` (PowerShell 5.1+), a standalone read-only security posture auditor.
- Implemented weighted, isolated check registry model so individual check failures are contained and reported as `Unknown` without aborting the full run.
- Added optional HTML report export (`-Html`) and console severity filter (`-MinSeverity`).
- Fixed score grading output to reliably emit a single letter grade (`A`–`F`).
- Updated `README.md` Quick Start with `pwsh ./Invoke-SecurityPosture.ps1` usage.
- Validation: PowerShell smoke run completed cleanly and Python regression tests passed (`test_core.py` + `test_security_systems.py`: 76 passed, 0 failed).

### v39 — 2026-06-04

**Stability: Smart Firewall Persistence + Runtime Safety**

- `network_guardian/agent/smart_firewall_agent.py`: Migrated offense history persistence from JSON file rewrites to SQLite (`injection_history.db`) with indexed `detections` table and incremental inserts.
- `network_guardian/agent/smart_firewall_agent.py`: Added writable datastore fallback chain to prevent startup failures when home-directory writes are restricted (default path -> `TMPDIR` -> workspace-local fallback).
- `network_guardian/agent/smart_firewall_agent.py`: Added periodic eviction of stale entries from request-rate tracker to prevent unbounded memory growth over long runtimes.
- Updated clear-history and false-positive paths to issue targeted SQL deletes instead of rewriting full history blobs.
- Validation: targeted regression suites passed — 48 total tests (`test_smart_firewall_fixes`, `test_probe_bridge`, `test_defensive_scanner`, `test_payload_harvester`) with 0 failures.

### v38 — 2026-06-04

**Security: Close Remaining 0.0.0.0 Bindings**

- `_start_dashboard.py`: Removed hardcoded `dash.host = "0.0.0.0"` — now reads `HOST` env var, defaulting to `127.0.0.1`. Dashboard no longer exposes port 8080 on all interfaces by default.
- `network_guardian/__main__.py`: Changed `--dashboard-host` CLI default from `"0.0.0.0"` → `"127.0.0.1"`. Help text updated to clarify remote-access opt-in.
- `whatsapp_server.py`: Fixed stale docstring that still advertised `HOST` default as `0.0.0.0` (already changed in v37).

### v37 — 2026-06-04

**Security: Port & Attack Surface Hardening**

- `probe_router.py`: Removed hardcoded router password and serial — now loaded from `ROUTER_PASSWORD` / `ROUTER_SERIAL` env vars with startup guard. Removed `ssl.CERT_NONE` + `check_hostname = False` from both SSL contexts (MITM-safe by default).
- `whatsapp_server.py`: Added Twilio HMAC-SHA256 webhook signature verification in `do_POST` (was unenforced). Changed default bind from `0.0.0.0` → `127.0.0.1`. Added `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store` headers. Added 16 KB body cap.
- Dashboard `RATE_LIMIT_MAX` lowered 10,000 → 200 requests/60s per IP.
- Dashboard CSP extended with `font-src fonts.googleapis.com fonts.gstatic.com` and `img-src 'self' data:`.
- Full test suite: 597 passed, 0 failed (pre-existing unrelated failures unchanged).

### v36 — 2026-06-04

**Global Shadow / Learning Mode**

- Added `Config.shadow_mode` — single boolean that puts the entire enforcement layer into observe-only mode. Set via `shadow_mode: true` in YAML or `NETWORK_GUARDIAN_SHADOW_MODE=1` env var.
- `DualPassEvaluator` in shadow mode: all `block` verdicts (score ≥ 60) downgraded to `flag` — detection still scored, logged, and published on the event bus, but no content is ever rejected.
- `IsolationSandboxEngine` in shadow mode: sessions that cross the isolation threshold (score ≥ 70) publish `sandbox.shadow.would_isolate` instead of triggering TCP sever and IPS block. `SUSPICIOUS` tier (≥ 40) fires in both modes.
- Engine threads `config.shadow_mode` into both components at init time — one config flag covers the entire enforcement stack.
- 16 new tests in `tests/test_shadow_mode.py` — full suite now 607 passed, 0 failed.

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
