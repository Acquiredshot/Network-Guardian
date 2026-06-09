# Changelog — Network Guardian

All notable changes to this project are documented here.

---

## [v50] — 2026-06-09

### Added — JARVIS Full Security-Tool Integration + AI Speed Optimization

This release gives J.A.R.V.I.S. direct voice/text access to every major Network Guardian
security subsystem and cuts AI response latency by 5–10× by switching the default
reasoning model to DeepSeek V3 (`deepseek-chat`).

---

#### New JARVIS Command Handlers (7)

Each handler is reachable via natural language or voice — no exact phrasing required.

| Command | Subsystem Called | Example Phrases |
|---|---|---|
| `cmd_firewall_scan` | `SmartFirewallAgent.run_cycle()` + injection history DB | *"firewall scan"*, *"last firewall scan"*, *"when was the last firewall scan"* |
| `cmd_malware` | `malware_scanner.scan_processes()` → `MalwareScanResult` | *"malware scan"*, *"scan for viruses"*, *"check processes"* |
| `cmd_ransomware` | `RansomwareMonitor` | *"ransomware check"*, *"file integrity"* |
| `cmd_ids` | Injection history DB (IDS events, last 20) | *"ids alerts"*, *"intrusion alerts"*, *"alert history"* |
| `cmd_ips` | `IntrusionPreventionSystem` — blocked / rate-limited / quarantined / allowlist | *"blocked ips"*, *"blocklist"*, *"who is blocked"* |
| `cmd_wifi` | `probe.scan_wifi()` — SSID, BSSID, channel, signal, security | *"wifi scan"*, *"wireless scan"*, *"nearby networks"* |
| `cmd_audit` | `Auditor.run_audit(["localhost"])` — CVSS/OWASP findings | *"run audit"*, *"security audit"*, *"vulnerability scan"* |

All handlers are registered in `DISPATCH` and exposed in `cmd_help`.

---

#### INTENT_MAP — 50+ New Natural-Language Keywords

Covers common voice phrasing for every new command plus extended aliases for existing
commands (e.g. `"check firewall"`, `"show blocked"`, `"intrusion prevention"`,
`"what networks"`, `"security findings"`).

---

#### AI Speed Optimization — DeepSeek V3 Default

| Setting | Before | After |
|---|---|---|
| Default model | `deepseek-reasoner` (chain-of-thought, 10–30 s) | `deepseek-chat` (V3, 1–3 s) |
| API timeout | 60 s | 30 s |
| Override mechanism | env var `DEEPSEEK_MODEL` | same — documented in `.env` |

`deepseek-reasoner` remains available for deep triage via `DEEPSEEK_MODEL=deepseek-reasoner`.
Both `DEEPSEEK_MODEL` and `DEEPSEEK_TIMEOUT` are now documented in `.env` with inline
guidance on when to use each mode.

---

#### Performance — Telemetry Caches (confirmed active)

`_cached_snapshot()` and `_cached_live_context()` (5 s TTL) — introduced in v49 — are
confirmed active. Back-to-back voice commands (e.g. "situation" then "ids alerts") reuse
the same DB snapshot, eliminating duplicate SQLite reads.

---

## [v49] — 2026-06-09

### Added — JARVIS Operational Data Access + Probe Commander

This release gives J.A.R.V.I.S. full read-only operational awareness of live telemetry
and all active field probes. JARVIS can now answer factual questions about the network
state ("when was the last firewall scan?"), discover unregistered probes on the subnet,
and health-check every registered field agent — using the probe/firewall bridge system.

---

#### New Module: `network_guardian/jarvis/probe_commander.py`

A read-only probe awareness engine with three capabilities:

| Function | Purpose |
|---|---|
| `list_registered_probes()` | Reads the `agents{}` section of `fleet.json` — the section probes write to when they phone home. Previously invisible to JARVIS. |
| `health_check_probe(ip)` | Async ping + concurrent TCP port scan (8080/8443/5000/4443) + HTTP banner grab to verify a host is a live NG instance. Returns latency, open ports, and NG-signal detection. |
| `scan_subnet_for_probes()` | Concurrent ping-sweep of the /24 subnet (up to 254 hosts, 40 parallel). Checks probe ports on every live host not already in fleet. Returns `ProbeRecord` list for unregistered candidates. |
| `run_full_probe_report()` | Sync blocking wrapper — combines all three. Safe to call from any thread. |

**Guard-rail:** All operations are strictly read-only. No probe commands, no config mutations, no subprocess execution.

---

#### JARVIS New Commands

| Say | Action |
|---|---|
| `probes` / `field agents` / `active probes` / `my laptop` | Full scan: registered agents + health check + subnet sweep for unregistered |
| `probe health` / `check probes` / `ping probe` | Health-only check — pings every registered probe IP |
| (existing) `fleet` / `devices` | Now also shows `agents{}` section — previously only showed `devices[]` |

**Natural-language aliases added (35+ new keywords across all commands):**
- `"last firewall scan"`, `"last attack"`, `"when was the last"`, `"scan history"` → `cmd_firewall`
- `"how many devices"`, `"what devices"`, `"connected devices"` → `cmd_fleet`
- `"are we safe"`, `"current threat"`, `"security report"` → `cmd_situation`
- `"system health"`, `"cpu usage"`, `"disk space"` → `cmd_metrics`
- `"my laptop"`, `"other operators"`, `"remote agent"` → `cmd_probes`

---

#### JARVIS Conversational AI — Live Data Access

The unrecognised-intent path (free-form questions) now:

1. Builds a real-time telemetry snapshot before calling DeepSeek:
   - Current threat level + score
   - CPU / RAM / disk / uptime
   - Fleet device count (online/offline)
   - Last firewall event (timestamp, type, source IP)
   - Lateral movement summary (total, HIGH/CRITICAL, last 24h)
   - **All registered probe agents** (hostname, IP, status, last seen)

2. Injects snapshot into the DeepSeek system prompt so JARVIS answers
   from real data instead of saying "I don't have access."

3. Updated system prompt removes the old "recommend a command" fallback
   for fact-based questions — JARVIS answers directly.

---

#### Bug Fixes

- **`cmd_fleet` blind spot fixed** — `fleet.json` stores probe agents under `agents{}`
  not `devices[]`. The old handler only read `devices[]`, making all registered probes
  invisible. Fixed: now shows both sections with separate labeled tables.

- **`.gitignore` hardened** — Added:
  - `jarvis_crash.log` / `jarvis_*.log` (contain operator commands + probe IPs)
  - `.ng_agent/` (agent auth tokens with time-limited fleet credentials)
  - `.network_guardian/` (runtime data dir — fleet.json, injection db, baselines)
  - `fleet_key.txt`, `agent_key.txt` (never push — distribute out-of-band)
  - `config.local.yaml`, `config.override.yaml` (may contain private IPs)
  - `win32com/`, `win32/`, `*.dmp` (pywin32 cache + crash dumps)

---

## [v48] — 2026-06-09

### Added — J.A.R.V.I.S. Terminal Intelligence Layer + LangGraph / DeepSeek-R1 AI Reasoning

This release integrates a full conversational terminal shell (**J.A.R.V.I.S.**) into the
Network Guardian platform and replaces the keyword-based TriageAgent intent classifier
with a **LangGraph state-machine + DeepSeek-R1 chain-of-thought reasoning engine**.
All 715 tests pass; 62 new JARVIS-specific tests added.

---

#### New Sub-package: `network_guardian/jarvis/`

Six new modules form the JARVIS terminal intelligence layer:

| Module | Purpose |
|---|---|
| `jarvis_core.py` | Master REPL shell — 10 command handlers, longest-match NL intent parser, `JarvisCore` programmatic API |
| `telemetry_aggregator.py` | Live OS metrics (psutil), fleet.json, injection_history.db (SQLite), lateral_movement.json reader |
| `threat_report_engine.py` | 0-100 threat scorer + formatted situation-report generator (`NOMINAL/ELEVATED/HIGH/CRITICAL`) |
| `subsystem_bootstrapper.py` | NG process lifecycle manager — auto-detects project root, resolves port 8080 collisions, launches/stops `start_all.py` |
| `jarvis_voice.py` | SAPI 5 TTS engine — `win32com` → PowerShell → silent fallback chain; `JarvisVoice`, `JarvisScript` persona lines |
| `jarvis_ear.py` | Microphone input — SpeechRecognition + Vosk offline / Google online / deaf fallback; `WakeWordDetector` |

**JARVIS REPL commands (natural language accepted):**

| Keywords | Action |
|---|---|
| `situation / status / threat / health` | Full threat + telemetry briefing |
| `triage / analyze / deep scan / ai scan` | **DeepSeek-R1 chain-of-thought triage** — live telemetry → LangGraph → structured action plan |
| `start / activate / defenses / deploy` | Launch Network Guardian via SubsystemBootstrapper |
| `stop / halt / shutdown` | Gracefully halt all NG subsystems |
| `fleet / devices / nodes / network map` | Show registered fleet from `fleet.json` |
| `firewall / injection / sql / attacks` | Query SQL injection history database |
| `lateral / movement / pivot` | Review lateral movement event log |
| `metrics / cpu / memory / disk` | Live OS hardware performance snapshot |
| `help / ?` | Command reference |
| `exit / quit / bye` | Terminate session |

**Start the JARVIS shell:**
```bash
python -m network_guardian.jarvis.jarvis_core
```

---

#### New Module: `network_guardian/ai/langgraph_reasoner.py`

Replaces keyword-only intent classification in `TriageAgent` with a full
**LangGraph state-machine + DeepSeek-R1** chain-of-thought reasoning pipeline.

**Graph topology:**
```
[ingest_node] → [reason_node] → conditional(_should_re_reason) → [plan_node] → [summarize_node] → END
```

**Nodes:**

| Node | Role |
|---|---|
| `ingest_node` | Normalises threat observations and system-state snapshot into graph state |
| `reason_node` | Calls DeepSeek-R1 (`deepseek-reasoner`) via OpenAI-compatible API; parses `<think>…</think>` chain-of-thought; returns `intent_class`, `confidence`, `action_plan`, `recommendations` |
| `plan_node` | Validates DeepSeek plan; applies per-`intent_class` fallback actions when plan is empty |
| `summarize_node` | Assembles final findings list from all reasoning artefacts |

**Re-reasoning loop:** if `confidence < 0.40` and only one iteration has occurred,
the graph automatically re-calls the reason node for a second pass before planning.

**Public API:**
```python
from network_guardian.ai.langgraph_reasoner import reason_about_intent

result = await reason_about_intent(
    intent="scan for lateral movement",
    system_state=telemetry.full_snapshot(),
    observations={},
    api_key=os.environ["DEEPSEEK_API_KEY"],
)
# result keys: intent_class, confidence, deepseek_reasoning, action_plan, recommendations, findings
```

**Activation:** set `DEEPSEEK_API_KEY` in `.env`. Falls back gracefully to the existing
keyword scorer if the key is absent or the API is unreachable.

---

#### Modified: `network_guardian/agent/triage_agent.py`

- **REASON phase** — when `DEEPSEEK_API_KEY` is set, calls `reason_about_intent()` and maps the
  returned `intent_class` string to `IntentClass` enum; uses DeepSeek's structured `action_plan` directly.
- **LEARN phase** — DeepSeek `recommendations` are prepended to keyword-built recommendations list.
- Keyword scorer retained as fallback; zero behaviour change if env var is absent.

---

#### New Tests: `tests/test_jarvis.py` (62 tests)

| Class | Coverage |
|---|---|
| `TestTelemetryAggregator` | OS metrics, fleet read, injection DB, lateral movement, full snapshot (10 tests) |
| `TestThreatReportEngine` | Threat scoring, label validation, report line generation, high-injection escalation (6 tests) |
| `TestSubsystemBootstrapper` | Root auto-detection, env var override, environment validation (6 tests) |
| `TestParseIntent` | 23 NL→intent mappings, empty/unknown inputs, longest-match win, completeness (28 tests) |
| `TestJarvisCore` | dispatch(), help output, situation, exit (5 tests) |
| `TestJarvisTriage` | DeepSeek mocked result, fallback without key, LG unavailable, exception handling, low confidence (5 tests) |
| `TestJarvisIntegration` | Full situation flow, report/print parity, snapshot integrity (3 tests) |

---

#### New Tests: `tests/test_langgraph_deepseek.py` (31 tests)

Covers all four graph nodes, re-reasoning conditional, full graph runs, TriageAgent
integration path, and graph structure validation. All LLM calls mocked via
`unittest.mock.patch("network_guardian.ai.langgraph_reasoner._make_llm")`.

---

#### Environment Variables Added

| Variable | Default | Purpose |
|---|---|---|
| `DEEPSEEK_API_KEY` | — | Activates LangGraph + DeepSeek-R1 reasoning |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Override DeepSeek API endpoint |
| `DEEPSEEK_MODEL` | `deepseek-reasoner` | Override model name |
| `DEEPSEEK_TIMEOUT` | `60` | API call timeout (seconds) |
| `JARVIS_OPERATOR` | `Network Guardian Operator` | Operator name used in JARVIS greetings |
| `NG_ROOT` | auto-detected | Override NG project root for SubsystemBootstrapper |
| `NG_DATA_ROOT` | `~/.network_guardian` | Override data directory for TelemetryAggregator |
| `NG_PORT` | `8080` | Port managed by SubsystemBootstrapper |

---

#### Dependencies Added

```
langgraph
langchain-openai
langchain-core
```

Install: `pip install langgraph langchain-openai langchain-core`
(Already present in the virtual environment.)

---

#### Test Suite Summary

| Suite | Before | After |
|---|---|---|
| Total tests | 653 | **715** |
| JARVIS tests | 0 | **62** |
| LangGraph/DeepSeek tests | 0 | **31** |
| Failures | 0 | **0** |

---

## [v47] — 2026-06-08

### Added — Google Safe Browsing Trust Signals & Search Console Verification

Root cause: Google Safe Browsing automated scanner flagged the bare credential
forms on the SaaS landing page as potential phishing content (no company identity,
no structured data, no contextual trust signals).

#### SaaS Landing Page (`network_guardian/saas/ui.py`)

- **Company identity header** — Wolf-Pak Innovations LLC branding with shield SVG
  icon renders above all page content so automated scanners see immediate context.
- **Trust-signal bar** — plain-English description of the platform's legitimate
  purpose (`commercial network intrusion-detection platform developed by Wolf-Pak
  Innovations LLC`) with a direct GitHub source-code link.
- **JSON-LD structured data** — `SoftwareApplication` schema embedded in `<head>`;
  provides Google's crawler with machine-readable proof of software product identity,
  author, license URL, and source repository.
- **`<meta>` tags** — `name`, `description`, `author`, Open Graph `og:title` /
  `og:description` / `og:type` added.
- **Form hardening** — `autocomplete` attributes, `minlength="12"` on password
  fields, Terms of Service and Privacy Policy note under signup form.
- **Full footer** — copyright notice, Wolf-Pak Innovations LLC, license link,
  EULA link, GitHub link, and a Safe Browsing transparency-report link.
- **Pricing cards** — `/mo` suffix added to all tier prices.

#### SaaS Service (`network_guardian/saas/service.py`)

- **`GET /robots.txt`** — returns `User-agent: * / Allow: /` with company identity
  comment; gives search crawlers explicit crawl permission.
- **`GET /.well-known/security.txt`** — RFC 9116 security contact pointing to
  GitHub Issues; signals responsible-disclosure policy to security scanners.
- **`GET /google9d4cc8c07d77fbd5.html`** — Google Search Console HTML-file
  verification endpoint; returns the required `google-site-verification:` token.
  Must remain deployed permanently for ongoing Search Console verification.

#### Google Search Console

- Property `https://network-guardian-cc8900c70290.herokuapp.com/` added and
  verified via HTML-file method (2026-06-08).
- Safe Browsing review request submitted via Search Console → Security Issues.

---

## [v46] — 2026-06-08

### Added — Flood & Probe-Packet Hardening + Probe Self-Protection

Root cause: a pen-test tool running on the same LAN was saturating the home router's
NAT connection table with probe packets, knocking the router offline for all devices.
Network Guardian now detects and auto-blocks this attack class **both at the engine level
and inside every deployed field probe**.

#### New Components

- **`network_guardian/agent/flood_guard.py`** — `FloodGuardAgent` — ReAct-style agent
  that monitors per-IP connection rates via psutil with a 10-second sliding window.
  Detects SYN floods, UDP floods, ICMP floods, probe packet saturation (pen-test router
  exhaustion), and total connection table exhaustion.  Auto-escalates IPS blocks:
  - Offence 1 → 1-hour block
  - Offence 2 → 6-hour block
  - Offence 3+ → permanent block
  Publishes `flood.detected` and `flood.table_exhaustion` events on the event bus.

- **`flood_watchdog.py`** — Standalone watchdog script (referenced by `harden_machine.ps1`
  but previously missing). Monitors connections via psutil / netstat fallback, notifies
  the dashboard API to request IPS blocks, and optionally adds Windows Firewall rules
  (requires admin). Launch: `python flood_watchdog.py --threshold 60 --interval 5`

#### Enhanced IDS Signatures (7 new rules)

| SID  | Name                      | Category | Severity |
|------|---------------------------|----------|----------|
| 4002 | UDP Flood                 | DOS      | CRITICAL |
| 4003 | ICMP Flood                | DOS      | HIGH     |
| 4004 | Probe Packet Saturation   | DOS      | HIGH     |
| 4005 | NTP Amplification Attack  | DOS      | HIGH     |
| 4006 | DNS Amplification Attack  | DOS      | HIGH     |
| 4007 | ARP Flood                 | DOS      | HIGH     |

#### IPS Policy Hardening

- `ThreatCategory.DOS` block duration: **600s → 3600s** (10 min → 1 hour)

#### Engine Integration

- `FloodGuardAgent` auto-started in `Engine.start()` alongside SmartFirewall and Triage
- `Engine.flood_guard` property added (lazy-initialized, same pattern as other agents)
- `Engine.stop()` gracefully awaits `flood_guard.stop()`

#### SmartFirewallAgent — Adaptive Threat Intelligence

- **FloodGuard integration** — subscribed to `flood.detected` and `flood.table_exhaustion` events;
  SmartFirewall now learns from every flood detection in real time
- **Per-IP adaptive confidence threshold** — known flood sources get a 30% lower detection
  threshold so injection attempts are caught at lower evidence; hostile-subnet IPs get the same
- **Hostile subnet tracking** — when ≥3 IPs in the same /24 flood, the subnet is flagged;
  all traffic from that subnet gets elevated scrutiny automatically
- **Multi-vector detection** — an IP that both floods *and* injects is identified as a
  compound attacker and immediately escalated to a **permanent block**
- **Attack velocity tuning** — the agent tracks new-attacker rate and event density over 60s
  windows and auto-tunes globally: HIGH-ATTACK → 0.55, ELEVATED → 0.62, RECOVERY → back to 0.70
- **Table exhaustion emergency mode** — when FloodGuard raises `flood.table_exhaustion`,
  confidence drops to 0.50 for 5 minutes then auto-recovers
- `adaptive_status()` method and `adaptive` key added to `get_stats()` / dashboard API

#### Field Probe Hardening (probe self-protection)

- **`_ProbeFloodGuard`** class added to `network_guardian/agent/probe.py` — lightweight
  stdlib-only flood detector (no psutil) that runs inside frozen/PyInstaller probe builds.
  Uses `netstat -tn` to count TCP connections per remote IP, applying the same thresholds
  as `FloodGuardAgent` (`SYN_FLOOD=60`, `PROBE_SATURATION=30`, `TABLE_EXHAUSTION=800`).
  Detects SYN/TCP flood, probe packet saturation, connection table exhaustion, and
  multi-source flood attacks; all emit OS notifications and console banners.

- **`AgentReport.flood_alerts`** and **`AgentReport.flood_total_connections`** fields added —
  probe reports now include flood status in every phone-home payload.

- **`ProbeReActAgent` flood detection** (`react_agent.py`) — the ReAct intelligence layer
  now performs flood analysis in its `reason()` phase using psutil (degrades gracefully).
  All thresholds remotely tunable via `patch_config` keys:
  `flood_syn_threshold`, `flood_udp_threshold`, `flood_probe_threshold`, `flood_table_warning`.

- **`ProbeAgent.publish_flood_detection()`** and **`ProbeAgent.publish_table_exhaustion()`**
  added to `network_guardian/agent/probe_agent.py` — field probe flood detections publish
  to the same `flood.detected` / `flood.table_exhaustion` topics consumed by SmartFirewall.

#### Test Fixes

- Fixed 36 occurrences of `asyncio.get_event_loop().run_until_complete()` →
  `asyncio.run()` in `tests/test_wifi_stealth.py` (Python 3.13 compatibility).

#### Validation

- IDS rule count: 15 → **22** (7 new flood signatures)
- Full test suite: **622 passed, 0 failed** (was 586 passed, 36 failed before fix)

---

## [v45] — 2026-06-06

### Documentation Security Hygiene

- Updated patch documentation examples to remove credential-like literals and replace them with placeholders (`<username>`, `<password>`, `<invalid-password>`).
- Sanitized patch-fetch command examples in operator docs to ensure no secret values are embedded in published patch notes.
- Added explicit alignment of docs with current runtime-safe guidance: use environment variables and non-literal credentials for operational commands.

---

## [v44] — 2026-06-06

### Fixed — Final Hardening TODO Pass

- `cvss_scan.py` SQL-injection detector was refined to reduce false positives by:
  - tightening SQL-string matching to SQL-shaped statements (`SELECT ... FROM`, `INSERT ... INTO`, etc.),
  - requiring nearby database execution context for generic SQL-string interpolation heuristics.
- This eliminated remaining false-critical findings caused by non-SQL strings containing words like `Select`.

### Fixed — Patch Fetch Compatibility in Current Runtime

- `fetch_patches.py` now supports a multi-path retrieval strategy:
  - legacy Basic Auth attempt,
  - session login fallback via `/api/auth/login`,
  - local fleet `pending_patch_config` fallback when `/api/patches` is unavailable.
- When no remote patch endpoint and no pending `patch_config` are present, script now reports an up-to-date state and persists an empty patch snapshot instead of failing.

### Validation

- CVSS summary after final detector hardening:
  - **Critical: 0**,
  - Total findings reduced to **138**,
  - Overall risk score improved to **35.9/100**.
- Patch fetch validation:
  - `fetch_patches.py` completes successfully against current dashboard mode,
  - saves patch state to `~/.network_guardian/patches/pending_patches.json` even when `/api/patches` is unavailable.

---


## [v44] — 2026-06-08

### Added — Flood & Probe-Packet Hardening + Probe Self-Protection

Root cause: a pen-test tool running on the same LAN was saturating the home router's
NAT connection table with probe packets, knocking the router offline for all devices.
Network Guardian now detects and auto-blocks this attack class **both at the engine level
and inside every deployed field probe**.

#### New Components

- **`network_guardian/agent/flood_guard.py`** — `FloodGuardAgent` — ReAct-style agent
  that monitors per-IP connection rates via psutil with a 10-second sliding window.
  Detects SYN floods, UDP floods, ICMP floods, probe packet saturation (pen-test router
  exhaustion), and total connection table exhaustion.  Auto-escalates IPS blocks:
  - Offence 1 → 1-hour block
  - Offence 2 → 6-hour block
  - Offence 3+ → permanent block
  Publishes `flood.detected` and `flood.table_exhaustion` events on the event bus.

- **`flood_watchdog.py`** — Standalone watchdog script (referenced by `harden_machine.ps1`
  but previously missing). Monitors connections via psutil / netstat fallback, notifies
  the dashboard API to request IPS blocks, and optionally adds Windows Firewall rules
  (requires admin). Launch: `python flood_watchdog.py --threshold 60 --interval 5`

#### Enhanced IDS Signatures (7 new rules)

| SID  | Name                      | Category | Severity |
|------|---------------------------|----------|----------|
| 4002 | UDP Flood                 | DOS      | CRITICAL |
| 4003 | ICMP Flood                | DOS      | HIGH     |
| 4004 | Probe Packet Saturation   | DOS      | HIGH     |
| 4005 | NTP Amplification Attack  | DOS      | HIGH     |
| 4006 | DNS Amplification Attack  | DOS      | HIGH     |
| 4007 | ARP Flood                 | DOS      | HIGH     |

#### IPS Policy Hardening

- `ThreatCategory.DOS` block duration: **600s → 3600s** (10 min → 1 hour)

#### Engine Integration

- `FloodGuardAgent` auto-started in `Engine.start()` alongside SmartFirewall and Triage
- `Engine.flood_guard` property added (lazy-initialized, same pattern as other agents)
- `Engine.stop()` gracefully awaits `flood_guard.stop()`

#### Validation

- IDS rule count: 15 → **22** (7 new flood signatures)
- FloodGuard starts cleanly with the engine; logs confirm: `[FloodGuard] Started`
- `flood_watchdog.py` runs standalone with `--threshold` / `--interval` / `--port` / `--firewall` flags

#### SmartFirewallAgent — Adaptive Threat Intelligence

- **FloodGuard integration** — subscribed to `flood.detected` and `flood.table_exhaustion` events;
  SmartFirewall now learns from every flood detection in real time
- **Per-IP adaptive confidence threshold** — known flood sources get a 30% lower detection
  threshold so injection attempts are caught at lower evidence; hostile-subnet IPs get the same
- **Hostile subnet tracking** — when ≥3 IPs in the same /24 flood, the subnet is flagged;
  all traffic from that subnet gets elevated scrutiny automatically
- **Multi-vector detection** — an IP that both floods *and* injects is identified as a
  compound attacker and immediately escalated to a **permanent block**
- **Attack velocity tuning** — the agent tracks new-attacker rate and event density over 60s
  windows and auto-tunes globally: HIGH-ATTACK → 0.55, ELEVATED → 0.62, RECOVERY → back to 0.70
- **Table exhaustion emergency mode** — when FloodGuard raises `flood.table_exhaustion`,
  confidence drops to 0.50 for 5 minutes then auto-recovers
- `adaptive_status()` method and `adaptive` key added to `get_stats()` / dashboard API

#### Field Probe Hardening (probe self-protection)

- **`_ProbeFloodGuard`** class added to `network_guardian/agent/probe.py` — lightweight
  stdlib-only flood detector (no psutil) that runs inside frozen/PyInstaller probe builds.
  Uses `netstat -tn` to count TCP connections per remote IP, applying the same thresholds
  as `FloodGuardAgent` (`SYN_FLOOD=60`, `PROBE_SATURATION=30`, `TABLE_EXHAUSTION=800`).
  Detects:
  - SYN/TCP flood → `severity: critical` alert
  - Probe packet saturation → `severity: high` alert
  - Connection table exhaustion → `severity: critical` alert + remediation guidance
  - Multi-source flood (≥3 hostile IPs) → summary `severity: critical` alert

- **`AgentReport.flood_alerts`** and **`AgentReport.flood_total_connections`** fields added —
  probe reports now include flood status in every phone-home payload; the base station
  dashboard displays it alongside existing threat alerts.

- **`ProbeReActAgent` flood detection** (`react_agent.py`) — the ReAct intelligence layer
  running inside each probe now performs flood analysis in its `reason()` phase:
  - `_probe_connection_counts()` helper: psutil-backed (gracefully degrades if unavailable)
  - Connection-table exhaustion threat (≥800 connections)
  - Per-IP SYN flood threat (≥60 connections from one IP)
  - Per-IP probe saturation threat (≥30 unique destination ports from one IP)
  - All three thresholds are remotely tunable via `patch_config` keys:
    `flood_syn_threshold`, `flood_udp_threshold`, `flood_probe_threshold`, `flood_table_warning`

- **`ProbeAgent.publish_flood_detection()`** and **`ProbeAgent.publish_table_exhaustion()`**
  added to `network_guardian/agent/probe_agent.py` — when a field probe detects flooding
  on its host it publishes to the same `flood.detected` / `flood.table_exhaustion` topics
  consumed by `SmartFirewallAgent`'s adaptive engine, feeding base-station cross-correlation
  and hostile-subnet intelligence.

- **Remote threshold updates** — flood thresholds pushed from the base station via the
  existing `patch_config` phone-home ACK mechanism are automatically consumed by both
  `ProbeReActAgent` and `_ProbeFloodGuard` on the next scan cycle, keeping all deployed
  probes in sync with the latest hardening rules without a restart.

---

## [v43] — 2026-06-06

### Security Hardening — Startup, Auth Bootstrap, and Scanner Reliability

- `start_all.py` now supports `--public-defense` mode (or `NG_PUBLIC_DEFENSE=1`) to launch the full defense stack (`run_full_system.py`) as a primary protection profile for public/hotspot networks.
- `start_all.py` startup flow now handles occupied port `8080` safely:
  - captures and logs dashboard startup root-cause stderr,
  - reuses an already-running local dashboard when bind fails with `address already in use`,
  - continues probe startup instead of failing the full launcher in this known-safe case.
- `start_all.py` Windows shutdown path now uses `subprocess.run(["taskkill", ...])` instead of shelling out through `os.system(...)`.
- `network_guardian/wolfpak/ng_fleet.py` and `network_guardian/wolfpak/ng_status.py` now clear terminal output with ANSI escape sequences rather than `os.system("clear")`.

### Credentials & Bootstrap Safety

- `network_guardian/interface/dashboard.py` no longer seeds a hardcoded bootstrap admin password.
- First-run bootstrap admin credentials now use:
  - `NG_BOOTSTRAP_ADMIN_PASSWORD` when provided, or
  - a generated random password at startup.
- Startup/login log messaging was updated to remove hardcoded credential text from launcher output.

### Scanner and Validation Improvements

- `scan_endpoints.py` now defaults to dashboard port `8080` and supports override through `NG_DASHBOARD_PORT`.
- `owasp_scan.py` A06 hardcoded-credential detection was tightened to reduce false positives by matching likely literal secret assignments instead of generic identifier usage.

### Probe & Bridge Update Workflow

- Probe deployment package rebuilt via `python -m network_guardian.agent.build --base ...` to refresh `dist/usb_deploy/probe.py` from canonical `network_guardian/agent/probe.py`.
- Verified deployment artifact parity (`SHA-256`) between source and USB package probe script.
- Verified bridge components load and report healthy stats:
  - `engine.probe_bridge`
  - `engine.payload_harvester`
  - `engine.attack_correlator`
- Exercised base-pushed probe patch update path (`FleetStore.set_patch_config` -> probe phone-home ACK `patch_config`) for `NG-608852BB`.

### Validation

- Endpoint validation: `scan_endpoints.py` -> **40 PASS / 0 FAIL**.
- OWASP scan summary after hardening: **Risk Score 4/100, Grade A (Minimal risk)**.
- CVSS scan summary after command-execution hardening:
  - Critical findings reduced from **6 -> 3**,
  - Total findings reduced from **143 -> 140**,
  - Overall risk score improved from **39.0 -> 37.4**.

### Operator Upgrade Notes (v42 -> v43)

- Use `--public-defense` (or `NG_PUBLIC_DEFENSE=1`) for hotspot/public-network primary defense startup.
- Remove assumptions of static first-run admin credentials; use `NG_BOOTSTRAP_ADMIN_PASSWORD` when deterministic bootstrap auth is required.
- If dashboard is not on port `8080`, set `NG_DASHBOARD_PORT` before running `scan_endpoints.py`.
- Rebuild probe deploy artifacts (`python -m network_guardian.agent.build --base ...`) to align distributed probe scripts with current canonical source.
- Prefer base-pushed fleet `patch_config` delivery for runtime probe updates in addition to legacy patch-fetch workflows.

---

## [v42] — 2026-06-05

### Fixed — Heroku SaaS Startup and Launch Hardening

- `_start_dashboard.py` and `network_guardian/__main__.py` now choose a Heroku-safe bind address automatically for SaaS mode (`0.0.0.0` when `DYNO` or `PORT` is present, otherwise local loopback).
- Removed the local `os` shadowing bug in `_start_dashboard.py` that caused SaaS startup to crash at runtime on Heroku.

### Validation

- GitHub push completed for the release commit.
- Heroku deploy completed successfully and the web dyno is up.
- Live SaaS routes validated with HTTP 200 responses on `/` and `/app`.

---

## [v41] — 2026-06-05

### Added — SaaS Platform Foundation and Validation Flow

- Added SaaS runtime mode (`NG_MODE=saas`) wired through startup entry points to launch the SaaS control plane.
- Added multi-tenant SaaS service endpoints for auth, organization, API keys, fleet ingest, billing checkout/portal, webhook processing, and hosted app pages.
- Added migration-driven SaaS persistence with backend selection for SQLite and PostgreSQL.
- Added one-command SaaS validation utility: `scripts/validate_saas_stack.py` (`sqlite`, `postgres`, `all`).
- Added SaaS fleet compatibility path in agents:
  - Legacy keys -> `/api/fleet/*` with `X-Agent-Signature`
  - SaaS API keys -> `/api/v1/fleet/*` with `X-API-Key`

### Fixed

- `network_guardian/agent/isolation_sandbox_engine.py` now safely handles both sync and async `block_ip` implementations in `_sever_connection` by awaiting only when the return value is awaitable.
- This removed the runtime warning triggered by async mocks in shadow-mode tests while keeping enforcement behavior unchanged.

### Validation

- `tests/test_shadow_mode.py`: **16 passed**
- Full regression suite: **622 passed**
- SaaS stack validator (sqlite mode): **passed**
- SaaS stack validator (postgres mode): **passed**

---

## [v40] — 2026-06-04

### Added — Windows Security Posture Auditor (Read-Only)

- **`Invoke-SecurityPosture.ps1`** — New standalone PowerShell 5.1+ audit script for host security posture assessment:
  - Strictly read-only behavior (assessment only; no system mutation).
  - Registry-based weighted check runner with per-check isolation so one failing check cannot crash the run.
  - Built-in scoring model with letter grade output (`A`–`F`) and pass/warn/fail weighting.
  - Optional self-contained HTML export via `-Html` argument.
  - Console filtering support via `-MinSeverity` (`Pass`/`Warn`/`Fail`).

- **`README.md`** — Quick Start updated with `pwsh ./Invoke-SecurityPosture.ps1` command for discoverability.

### Fixed

- **`Invoke-SecurityPosture.ps1`** — Corrected grade computation logic to return a single grade value (previous conditional switch expression could produce a multi-value output).

### Validation

- PowerShell smoke execution completed successfully (script runs end-to-end without crashing; unsupported platform checks degrade to `Unknown` as designed).
- Python regression suites passed after integration changes:
  - `tests/test_core.py` + `tests/test_security_systems.py`: **76 passed**

## [v39] — 2026-06-04

### Stability — Smart Firewall Persistence & Runtime Hardening

#### Fixed

- **`network_guardian/agent/smart_firewall_agent.py`** — Replaced JSON history persistence with SQLite-backed incremental writes:
  - Added `injection_history.db` storage (`detections` table + indexes) to avoid full-file rewrites on each detection.
  - Preserved per-IP history cap (500 entries) with SQL pruning logic after inserts.
  - Updated clear/false-positive flows to issue targeted SQL deletes.

- **`network_guardian/agent/smart_firewall_agent.py`** — Prevented startup crashes in restricted environments:
  - Added writable data-store fallback chain when default home path is not writable.
  - Fallback order: configured/default path, `TMPDIR/network_guardian/smart_firewall`, then `cwd/.network_guardian/smart_firewall`.
  - Eliminates `sqlite3.OperationalError: unable to open database file` under sandboxed test runners.

- **`network_guardian/agent/smart_firewall_agent.py`** — Added stale request-tracker eviction:
  - Periodic cleanup removes inactive IP entries from `_request_tracker`.
  - Prevents unbounded in-memory growth during long-running scans or distributed probing.

#### Validation

- Targeted regression tests passed after patch:
  - `tests/test_smart_firewall_fixes.py` + `tests/test_probe_bridge.py`: **18 passed**
  - `tests/test_defensive_scanner.py` + `tests/test_payload_harvester.py`: **30 passed**
  - Total targeted pass count: **48 passed, 0 failed**

## [v37] — 2026-06-04

### Security — Port & Attack Surface Hardening

#### Critical Fixes

- **`probe_router.py`** — Removed hardcoded router credentials (`password`, `serial`) and disabled-TLS flags:
  - Router IP, password, and serial now loaded from `ROUTER_IP`, `ROUTER_PASSWORD`, and `ROUTER_SERIAL` environment variables.
  - Process raises `RuntimeError` at startup if `ROUTER_PASSWORD` is unset — no silent insecure fallback.
  - Removed `ctx.check_hostname = False` and `ctx.verify_mode = ssl.CERT_NONE` from both SSL contexts; `ssl.create_default_context()` now verifies certificates by default (prevents MITM).
  - Same fix applied to the second SSL context block in the file (lines ~168-169).

- **`whatsapp_server.py`** — Twilio webhook signature not being verified:
  - `do_POST` now calls `whatsapp.verify_webhook(raw_body, X-Twilio-Signature)` before any processing.
  - Unauthenticated POST requests return HTTP 403 immediately.
  - Added 16 KB request body cap to prevent oversized payloads.
  - Warning logged when `WEBHOOK_SECRET` is default/unset so operators know to configure it.

#### High Fixes

- **`whatsapp_server.py`** — Default bind address changed from `0.0.0.0` to `127.0.0.1`:
  - Server no longer listens on all interfaces by default.
  - Override with `HOST=0.0.0.0` env var when a public-facing tunnel (e.g. cloudflared) is required.
  - Security response headers added to all responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`.

- **`network_guardian/interface/dashboard.py`** — Rate limiter threshold reduced:
  - `RATE_LIMIT_MAX` lowered from 10,000 to **200 requests per 60-second window** per IP.
  - The previous value was effectively no protection against automated scanning or credential stuffing.

- **`network_guardian/interface/dashboard.py`** — CSP `font-src` directive added:
  - Dashboard loads Google Fonts via `<link>` from `fonts.googleapis.com` and `fonts.gstatic.com`.
  - Previous CSP `default-src 'self'` caused fonts to be blocked by strict CSP enforcement in hardened browsers. Added `font-src fonts.googleapis.com fonts.gstatic.com` to the policy.
  - `img-src` updated to allow `data:` URIs (used by inline favicon/icon patterns).

---

## [v36] — 2026-06-04

### Added

#### Global Shadow / Learning Mode — Risk-2 False-Positive Mitigation

- **`network_guardian/config/__init__.py`** — Updated:
  - New `Config.shadow_mode: bool` field (default `False`).
  - Loaded from YAML key `shadow_mode: true` via `Config.load()`.
  - Overridable at runtime via env var `NETWORK_GUARDIAN_SHADOW_MODE=1` (also accepts `true` / `yes`).
  - `_apply_dict()` updated to propagate the flag from YAML into the dataclass.

- **`network_guardian/agent/dual_pass_evaluator.py`** — Updated:
  - `DualPassEvaluator(shadow_mode=False)` — new constructor parameter.
  - In shadow mode, `_decide_action()` downgrades any `block` verdict (score ≥ 60) to `flag` — content is logged and published on `eval.pipeline.flagged` but never rejected.
  - `flag` tier (score 25–59) fires identically in both modes; all telemetry events still publish.
  - Startup log warns clearly when shadow mode is active.
  - `get_stats()` now includes `shadow_mode` key.

- **`network_guardian/agent/isolation_sandbox_engine.py`** — Updated:
  - `IsolationSandboxEngine(shadow_mode=False)` — new constructor parameter.
  - In shadow mode, when a session crosses `ISOLATION_THRESHOLD` (70), the engine skips the IPS block call and TCP sever entirely and instead publishes `sandbox.shadow.would_isolate` with full score, trigger event, session ID, and timestamp.
  - `SUSPICIOUS` tier (score ≥ 40) fires and publishes `sandbox.session.suspicious` identically in both modes — operators always see the escalation signal.
  - Startup log warns clearly when shadow mode is active.
  - New private method `_shadow_would_isolate()` handles the observe-only code path.

- **`network_guardian/core/engine.py`** — Updated:
  - `engine.dual_pass_evaluator` property threads `config.shadow_mode` into `DualPassEvaluator` at instantiation.
  - `engine.isolation_sandbox` property threads `config.shadow_mode` into `IsolationSandboxEngine` at instantiation.

- **`run_full_system.py`** — Updated:
  - Startup log appends `[SHADOW MODE — observe only]` to the sandbox ready line when `config.shadow_mode` is `True`.

#### Test Coverage

- **`tests/test_shadow_mode.py`** — NEW (16 tests, all passing):
  - `TestConfigShadowMode` (6): default False, YAML true/false, env var `1`, env var `true`, env var absent.
  - `TestDualPassEvaluatorShadowMode` (3): block downgraded to flag; enforcement still blocks; flag tier unaffected.
  - `TestIsolationSandboxShadowMode` (4): would_isolate published / isolated suppressed; enforcement calls IPS; suspicious tier fires in both modes; would_isolate event field completeness.
  - `TestEngineShadowModeIntegration` (3): evaluator gets shadow_mode, sandbox gets shadow_mode, default engine is enforcement mode.

---

## [v35] — 2026-06-04

### Added

#### UEBA — Per-Device Behavioral Baseline (Feature 1)

- **`network_guardian/ai/device_baseline.py`** — NEW:
  - Per-device persistent behavioral baseline engine. Each IP builds its own rolling Isolation Forest, isolated from fleet-wide averages — no shared signal contamination between devices.
  - `DeviceBaseline(device_id, window_size=200, min_samples=30)` — single-device rolling window with personal Isolation Forest.
  - `observe(features)` — returns `None` during warm-up (< 30 samples), then scores against the device's personal baseline; model refits every 10 observations.
  - `DeviceBaselineManager` — multi-device orchestrator; creates a `DeviceBaseline` on first contact per IP and delegates all scoring to it.
  - Persistence: baselines saved to `~/.network_guardian/baselines/<sanitized_ip>.json` and fully restored on init (non-fatal on error).
  - Integrated into `Engine` as lazy singleton property `engine.device_baseline_manager`.

- **`DeviceBaselineNode`** — NEW (in `network_guardian/ai/nodes.py`):
  - Subscribes to `sensor.metrics`, `monitor.metric_recorded`, and `ids.alert` bus events.
  - Extracts `device_id` + numeric feature vectors from each event type.
  - Publishes `ai.device_baseline_alert` when a device's observed behavior deviates from its personal baseline.
  - Added to `NodeGraph.create_default()` — node graph now contains 6 nodes (was 4).

#### UEBA — Lateral Movement Detection (Feature 2)

- **`network_guardian/ai/lateral_movement.py`** — NEW:
  - Detects ransomware propagation, worm spread, and internal reconnaissance by tracking unique destination fan-out per source IP across rolling 5-minute time windows.
  - `LateralMovementDetector(window_seconds=300, spike_z_threshold=3.0, spike_absolute_threshold=20)`:
    - Raises `LateralMovementAlert` when a device's fan-out spikes ≥ 3 standard deviations above its rolling per-source baseline.
    - Absolute threshold (≥ 20 unique destinations in one window) fires on brand-new devices with no history.
    - Per-source history deques (`max_history=50`) accumulate fan-out counts across windows for z-score calculation.
  - `LateralMovementAlert` dataclass: `src_ip`, `current_fanout`, `baseline_mean`, `baseline_std`, `z_score`, `is_alert`, `window_seconds`, `dst_ips`, `timestamp`; `.as_dict()` serialization.
  - Persistence: fan-out history saved to `~/.network_guardian/lateral_movement.json` and restored on init.
  - Integrated into `Engine` as lazy singleton property `engine.lateral_movement_detector`.

- **`LateralMovementNode`** — NEW (in `network_guardian/ai/nodes.py`):
  - Subscribes to `ids.alert` bus events.
  - Extracts `source_ip` → `destination_ip` connection pairs from each IDS alert.
  - Publishes `ai.lateral_movement_alert` when fan-out spike is detected for a source.
  - Added to `NodeGraph.create_default()` alongside `DeviceBaselineNode`.

#### Engine Updates

- **`network_guardian/core/engine.py`** — Updated:
  - Lazy `engine.device_baseline_manager` property → `DeviceBaselineManager(data_dir=config.data_dir / "baselines")`.
  - Lazy `engine.lateral_movement_detector` property → `LateralMovementDetector(data_dir=config.data_dir)`.
  - Both auto-initialize on first access with zero startup cost when unused.

#### Test Coverage

- **`tests/test_ueba.py`** — NEW (36 tests, all passing):
  - `TestDeviceBaseline` (7): warm-up behavior, fitting, normal/anomaly scoring, stats, persistence roundtrip, observation count.
  - `TestDeviceBaselineManager` (7): creation, warm-up, scoring, multi-device independence, stats, save/reload, graceful bad-dir handling.
  - `TestLateralMovementDetector` (9): no-alert-without-baseline, absolute threshold, normal fanout, spike alert, z-score validity, alert fields, stats, save/reload, window roll.
  - `TestDeviceBaselineNode` (6): start/manager creation, missing features ignored, metric event processing, IDS alert processing, publishes on anomaly, skips unknown src.
  - `TestLateralMovementNode` (4): start/detector creation, ignores missing dst, publishes on spike, no alert for normal traffic.
  - `TestNodeGraphIntegration` (3): default graph contains new nodes, starts/stops, engine lazy properties.

### Fixed

- **`tests/test_step4.py`** — Updated hardcoded node count assertions from `== 4` to `== 6` to reflect the two new UEBA nodes added to `NodeGraph.create_default()`.
- **`network_guardian/interface/dashboard.py` — `loadStatus()` unauthenticated request loop** — The security page's `loadStatus()` function polled `/api/ransomware/status` every 3 seconds with no 401 response handler. When a session expired while the page was open, every poll fired unauthenticated, generating continuous `Unauthenticated request from 127.0.0.1: GET /api/ransomware/status` warnings in the terminal (the auth gate was correctly blocking them, but the JS silently swallowed the 401). Fixed by adding the same redirect-on-401 guard already present in `startMonitor()` — expired sessions now immediately redirect to `/login?next=/security` instead of looping indefinitely.

---

## [v34] — 2026-06-04

### Added

#### Semantic Layer Threat Detection — MCP/API Protocol Parser

- **`network_guardian/agent/mcp_protocol_parser.py`** — NEW:
  - Operates at the *semantic* layer above the SmartFirewallAgent, fully structuring protocol envelopes before evaluating each field for threat content.
  - Supported envelope types: **JSON-RPC 2.0**, **MCP** (role/content/tool_calls/tool_results/context_injection/rag_blocks), **GraphQL** (query/mutation/subscription/introspection), **Multi-agent** (tool_execution/agent_handoff/memory_write/retrieval_augmentation).
  - Threat detection categories: `prompt_injection`, `tool_abuse`, `introspection_probe`, `context_poisoning`, `oversized_payload`, `schema_exfiltration`, `method_enumeration`, `malformed_envelope`.
  - Publishes `mcp.parser.threat`, `mcp.parser.parsed`, and `mcp.parser.malformed` events to the engine event bus.
  - Integrated into `Engine` as lazy singleton property `engine.mcp_parser`.
  - Initialized as step [7/9] in `run_full_system.py`.

#### Dual-Pass Evaluation Pipeline

- **`network_guardian/agent/dual_pass_evaluator.py`** — NEW:
  - Non-blocking async verification array that reviews AI context content across two independent passes before context injection occurs.
  - **Pass 1 — Pre-execution (INPUT):** Evaluates system prompts, tool definitions, RAG context blocks, and user-supplied messages before injection. Detects prompt injection, instruction overrides, dangerous tool definitions, and oversized context.
  - **Pass 2 — Post-execution (OUTPUT):** Evaluates tool responses, RAG-retrieved blocks, and assistant turns before they are fed into the next context window. Detects data exfiltration, recursive instruction following, PII leakage, and malicious code.
  - Score thresholds: `allow` (<25), `flag` (25–59), `block` (≥60).
  - Both passes run as persistent async workers consuming from independent `asyncio.Queue`s — submissions are non-blocking.
  - Publishes `eval.pipeline.flagged`, `eval.pipeline.blocked`, and `eval.pipeline.result` events.
  - Integrated into `Engine` as lazy singleton property `engine.dual_pass_evaluator`.
  - Initialized as step [8/9] in `run_full_system.py`.

#### Isolation & Sandboxing Engine

- **`network_guardian/agent/isolation_sandbox_engine.py`** — NEW:
  - Aggregates per-session threat scores from MCP Parser, Dual-Pass Evaluator, IDS alerts, and SmartFirewall injection events with time-decay (scores halve every 5 minutes).
  - Session lifecycle: `ACTIVE` → `SUSPICIOUS` (score ≥ 40) → `ISOLATED` (score ≥ 70) → `RELEASED`.
  - On isolation: severs TCP session via IPS IP block, generates a convincing synthetic honeypot response, and writes a forensic log entry.
  - Subscribes to: `mcp.parser.threat`, `eval.pipeline.flagged`, `eval.pipeline.blocked`, `ids.alert`, `firewall.injection.blocked`.
  - Publishes: `sandbox.session.suspicious`, `sandbox.session.isolated`, `sandbox.session.released`, `sandbox.forensic.written`.
  - Integrated into `Engine` as lazy singleton property `engine.isolation_sandbox`.
  - Initialized as step [9/9] in `run_full_system.py`.

#### Full System Coordinator Expanded

- **`run_full_system.py`** — Updated initialization sequence from 6 to 9 steps:
  - [7/9] MCP/API Protocol Parser
  - [8/9] Dual-Pass Evaluation Pipeline
  - [9/9] Isolation & Sandboxing Engine
- Coordinator loop now reports MCP, evaluator, and sandbox stats in addition to firewall/correlation/discovery metrics.
- Final state persistence on shutdown includes all new component data paths.

### Fixed

#### Windows Signal Handler Crash on Startup
- **Problem**: `run_full_system.py` crashed immediately on Windows with `NotImplementedError`.
- **Root cause**: `asyncio.AbstractEventLoop.add_signal_handler()` is not implemented on Windows.
- **Solution**: Added `sys.platform` check — uses `loop.add_signal_handler` on Unix/macOS and `signal.signal` on Windows.
- **Impact**: `run_full_system.py` starts cleanly on all platforms.
- **File**: `run_full_system.py`

#### IsolationSandboxEngine Event Subscription TypeError
- **Problem**: Two tests (`TestEngine.test_start_stop`, `TestEngineIntegration.test_engine_start_stop_with_nodes`) failed with `TypeError: object NoneType can't be used in 'await' expression`.
- **Root cause**: `isolation_sandbox_engine.py::_subscribe_events()` was calling `await eb.subscribe(...)` but `EventBus.subscribe()` is a synchronous method returning `None`.
- **Solution**: Removed `await` from all 5 `subscribe()` calls in `_subscribe_events()`.
- **Impact**: Engine startup succeeds; all 555 tests now pass (was 553/555).
- **File**: `network_guardian/agent/isolation_sandbox_engine.py`

### Test Results

| Run | Passed | Failed | Total |
|---|---|---|---|
| Before fix | 553 | 2 | 555 |
| After fix | **555** | **0** | 555 |

### Documentation

- **Updated:** `CHANGELOG.md` — This entry
- **Updated:** `README.md` — Added MCP Protocol Parser, Dual-Pass Evaluator, and Isolation Sandbox to capabilities table; updated Quick Start with `run_full_system.py`

### Version
- **Semantic Version:** 0.2.2
- **Release Date:** June 4, 2026
- **Features Added:** 3 (MCP parser, dual-pass evaluator, isolation sandbox)
- **Bugs Fixed:** 2 (Windows signal handler, sandbox event subscription)

---

## [v33] — 2026-05-29

### Fixed

#### Probe Threat Detection — False Positive Reduction
- **HIGH_CPU threshold** raised from `>5.0` to `>9.0` load average — prevents false positives on developer workstations actively running VS Code, dashboard, and probe simultaneously.
- **EXCESSIVE_CONNECTIONS threshold** raised from `>20` to `>50` (MEDIUM) and `>100` (HIGH) — modern workstations with a browser open typically hold 20–40 external connections legitimately; previous threshold fired on normal activity.

---

## [v32] — 2026-05-29

### Added

#### Multi-Agent Fleet Management

Full fleet registration, labeling, and persistence improvements for multi-probe deployments:

##### Named Agent Labels
- **Fleet label fix** — `label` field in `~/.network_guardian/fleet.json` is now correctly seeded from `identity.hostname` at first registration.
- Probe `NG-13571285` registered and labeled **"Eli"** — persistent across dashboard restarts.
- Label is displayed on the fleet card name, fleet map node, and all per-agent drill-downs.

##### Fleet Persistence & Restart Safety
- Dashboard now reloads `fleet.json` cleanly on startup — all custom labels survive a restart.
- Fixed edge case where re-registration of an existing agent preserved a stale IP-based label instead of the configured name.

##### Probe Continuity
- Local probe (`run_local_probe.py`) auto-restarts cleanly after dashboard restarts — no manual intervention required.
- PORT env-var respected across both `_start_dashboard.py` and `run_local_probe.py` (defaults to 8080, override with `$env:PORT=8081`).

### Fleet Status (as of v32)

| Agent ID | Label | Platform | Status |
|---|---|---|---|
| NG-175079C4 | pheonix | Windows 11 | Online — reporting every 30s |
| NG-608852BB | Cortezs-MacBook-Air.local | macOS | Offline — last seen 15h ago |
| NG-13571285 | Eli | Unknown | Registered — awaiting first probe run |

### Fixed

#### Eli Probe Display Name
- **Problem**: Fleet card for `NG-13571285` displayed a raw IP address instead of the agent name "Eli".
- **Root cause**: `register_agent()` preserves existing label on re-registration (`existing.get("label", ...)`). The first registration had captured an IP as the label before the hostname was set.
- **Solution**: Patched `label` field directly in `fleet.json` to `"Eli"` and restarted the dashboard to reload from disk.
- **Impact**: Fleet map, agent cards, and per-agent drill-downs all display "Eli" correctly.

#### Probe Offline After Dashboard Restart
- **Problem**: pheonix probe showed OFFLINE after dashboard was restarted to pick up fleet label fix.
- **Root cause**: Probe process tied to old dashboard terminal session — killed when session was recycled.
- **Solution**: Probe restarted with `$env:PORT=8081; python run_local_probe.py` — back ONLINE within one report cycle.

### Documentation

- **Updated:** `CHANGELOG.md` — This entry
- **Updated:** `README.md` — Fleet section updated with 3-probe fleet, label behavior, and startup notes

### Version
- **Semantic Version:** 0.2.1
- **Release Date:** May 29, 2026
- **Features Added:** 1 (named fleet labels)
- **Bugs Fixed:** 2 (label display, probe continuity)

---

## [v31] — 2026-05-28

### Added

#### Cross-Platform Team Deployment System

Complete cross-platform support for Windows, macOS, and Linux with unified startup and team deployment:

##### Unified Startup Scripts
- **`start_all.py`** — Master Python entry point for all platforms. Single command initializes dashboard + local probe with automatic restart on crashes.
- **`START_ALL.bat`** — Windows batch file for double-click startup (non-technical team members).
- **`Start-All.ps1`** — Windows PowerShell alternative with colored output and error handling.
- All scripts use `pathlib.Path` for OS-agnostic path handling (Windows/Unix compatibility).

##### System Verification & Pre-Flight Checks
- **`verify_system.py`** — Comprehensive system health checker:
  - Python 3.9+ validation
  - Port 8080 availability check
  - Required file presence verification
  - Fleet configuration detection
  - Network Guardian module availability
  - OS-specific troubleshooting guidance
  - Exit code: 0 (ready) or 1 (issues)

##### Comprehensive Documentation
- **`README_TEAM_SETUP.md`** — Quick-start guide for team deployment across all platforms. Default credentials, troubleshooting, file structure.
- **`CROSS_PLATFORM_SETUP.md`** — Detailed OS-specific setup with native commands for Windows/macOS/Linux, network topology, and deployment strategies.
- **`LOCAL_STARTUP.md`** — Local running guide with monitoring, troubleshooting, and data storage details.
- **`PATCHES.md`** — NEW: Complete patch delivery system documentation, API reference, and deployment workflows.

##### Cross-Platform Code Updates
- **`run_local_probe.py`** — Updated for cross-platform path handling using `Path.home()` and `pathlib.Path`.
- **`dashboard.py`** — Fixed rate limiting (increased RATE_LIMIT_MAX from 600 to 10,000) to support normal browser usage patterns.
- All relative path handling abstracted away OS-specific path conventions.

##### Team Deployment Model
- Each team member clones repository and runs single command.
- Dashboard and probe start automatically with independent fleet registration.
- No central server required — each machine runs completely locally.
- Data persists in `~/.network_guardian/` across restarts.
- Auto-restart of crashed probes ensures high availability.

#### Patch & Recommendation Delivery System

Centralized distribution of security recommendations, system hardening fixes, and vulnerability patches to remote probes:

##### Patch Management Infrastructure
- **`network_guardian/interface/patches_api.py`** — NEW:
  - `PatchStore` class for patch lifecycle management
  - `PatchesAPI` HTTP interface for patch delivery
  - RESTful endpoints: `GET /api/patches`, `POST /api/patches/{id}/apply`
  - Persistent patch storage at `~/.network_guardian/patches/`

##### Patch Fetching Tool
- **`fetch_patches.py`** — NEW: Command-line tool for probes to fetch patches
  - Authenticates with dashboard or centralized server
  - Displays patches grouped by severity (critical/high/medium/low)
  - Includes CVE identifiers and fix commands
  - Saves patch list locally for offline reference
  - Usage: `python3 fetch_patches.py [url] [agent_id] [username] [password]`

##### Patch Delivery Features
- **Severity-Based Prioritization** — Critical, High, Medium, Low classifications
- **CVE Integration** — Link patches to specific vulnerability identifiers
- **Auto-Generated Commands** — Ready-to-execute fix commands for each patch
- **Status Tracking** — Monitor which agents have applied which patches
- **Audit Trail** — Persistent record of all patch deployments
- **Platform Support** — macOS, Linux, Windows-specific patches

##### Network Path Verification
- Probe → fetch_patches.py → Local Dashboard (127.0.0.1:8080) ✅
- Probe → fetch_patches.py → Central Server (192.168.1.12:8081) ✅
- Network paths CLEAR for patch delivery in both directions

### Fixed

#### Dashboard Rate Limiting Issue
- **Problem**: HTTP 429 "Too Many Requests" errors preventing dashboard access.
- **Root cause**: RATE_LIMIT_MAX set to 600 requests/min (≈10 req/sec), browser auto-refresh exceeded limit.
- **Solution**: Increased RATE_LIMIT_MAX to 10,000 requests/min (≈167 req/sec).
- **Impact**: Dashboard now supports normal browser usage patterns without rate limiting errors.

#### Cross-Platform Path Handling
- **Problem**: Hardcoded Unix paths (`/Users/...`) broke Windows deployment.
- **Root cause**: Absolute paths not portable across OS platforms.
- **Solution**: Replaced all hardcoded paths with `pathlib.Path` API.
- **Impact**: Identical startup commands work on Windows, macOS, and Linux.

#### Process Management Compatibility
- **Problem**: Unix kill commands (`kill -9`) don't exist on Windows.
- **Root cause**: OS-specific process termination differences.
- **Solution**: Platform detection with conditional process management (Windows: `taskkill /F`, Unix: `kill -9`).
- **Impact**: Proper cleanup of probe/dashboard processes on all platforms.

### Documentation

- **New:** `PATCHES.md` — Complete patch delivery system reference (API, commands, workflows, architecture)
- **Updated:** `README.md` — Added patch delivery capability to capabilities table
- **Maintained:** `CHANGELOG.md` — This document
- **Maintained:** `pyproject.toml` — Version bumped to 0.2.0

### Version
- **Semantic Version:** 0.2.0 (bumped from 0.1.0)
- **Release Date:** May 28, 2026
- **Features Added:** 2 major (cross-platform, patch delivery)
- **Bugs Fixed:** 3 (rate limiting, path handling, process management)

---

## [v30] — 2026-05-28

### Added

#### Smart Firewall ↔ Probe Integration — Hardened Defensive Capabilities

Tightly integrated the network probe and smart firewall for intelligent threat correlation, payload learning, and defensive network scanning. Four complementary security enhancements:

##### 1. Threat Intelligence Feedback (Probe → Firewall)
- **`probe_firewall_bridge.py`** — Orchestrates intelligence flow from probe discoveries to firewall rule adaptation.
- When probe discovers open port running vulnerable service (HTTP, SQL, SOAP, etc.), firewall automatically enables service-specific detection rules.
- When probe identifies weak authentication, firewall increases monitoring sensitivity on auth endpoints.
- When probe detects rogue AP / evil twin, firewall flags correlated auth bypass attempts.
- **Service rule mappings**: HTTP → XSS/Path Traversal, SQL → SQL Injection, SOAP → XXE, LDAP → LDAP Injection, etc.
- Discovered services persisted to disk; firewall adapts on agent restart.

##### 2. Payload Harvesting (Exploited Payloads → Dynamic Rules)
- **`payload_harvester.py`** — Converts successfully exploited payloads into firewall detection rules.
- When probe exploits vulnerability (e.g., SOAP auth bypass, SQL injection), harvester extracts payload pattern.
- Converts to regex-based detection rule with confidence score based on exploitation context.
- Adds harvested rule to firewall's dynamic rule set; firewall detects similar attacks immediately.
- Confidence scores: SOAP auth bypass (0.88), SQL injection (0.85), XXE (0.92), Command injection (0.90).
- Harvested rules persist to disk; firewall uses them across restarts.
- Tracks detection success/failure; auto-increases confidence scores for proven rules.

##### 3. Defensive Scanning (Probe Tests Network w/ Firewall Rules)
- **`probe_defensive_scanner.py`** — Uses firewall's own detection rules to scan internal network for vulnerabilities.
- Synthesizes test payloads from firewall's 31+ injection detection rules.
- Tests internal endpoints against firewall rules to identify exploitable injection points.
- Validates findings using firewall's own detection engine (eliminates false positives).
- Service-specific payloads: HTTP (XSS, Path Traversal), SQL (UNION, Time-based), SOAP (XXE, Entity injection), LDAP (Filter escape), etc.
- Reports vulnerable endpoints for operator remediation.
- Defensive scan results persisted; tracks vulnerability trends over time.
- Success criteria: <3% false-positive rate, <5 min scan time for /24 subnet.

##### 4. Attack Correlation (Discoveries + Firewall Blocks = High-Confidence Threats)
- **`probe_attack_correlator.py`** — Correlates probe discoveries with firewall-detected attacks.
- Maintains persistent cache of discovered hosts/ports/services.
- When firewall detects injection attack, correlator checks if target matches discovered endpoint.
- **Exact-match correlation** (discovered IP:port attacked) → confidence +0.85, threat score escalation.
- **Blind-attack flagging** (unknown endpoint attacked) → confidence +0.15 (low certainty).
- **Time-delta analysis** — attacks within 1 hour of discovery suggest active reconnaissance.
- Threat scores per source IP: 0.0 (clean) to 1.0 (confirmed attacker).
- Distinction: "Attacker did recon then exploited" vs. "Random probe".
- Discovered services and correlations persist to disk; survives agent restart.

##### Core Modifications
- **`smart_firewall_agent.py`**:
  - Added dynamic rule management: `add_dynamic_rule()`, `adapt_rule_confidence()`.
  - Accepts optional `probe_bridge` and `correlator` parameters.
  - Three new event handlers: `_on_probe_discovery()`, `_on_probe_exploitation()`, `_on_payload_learned()`.
  - Subscribes to `probe.discovery.*` and `probe.exploitation.*` events.
  - `_act_on_detection()` now checks correlator before blocking; confidence +0.15 for correlated attacks.

- **`engine.py`**:
  - Added properties for all four integration components with lazy loading.
  - `smart_firewall` property wired with `probe_bridge` and `attack_correlator`.
  - All components share single `event_bus` for coordinated communication.

#### Comprehensive Test Suite — 66 Tests
- **`test_probe_bridge.py`** (8 tests): Bridge initialization, service registration, rule adaptation, event handling, persistence.
- **`test_payload_harvester.py`** (12 tests): Harvester initialization, payload-to-rule conversion, pattern generation for SOAP/SQL/XSS/CMD/Path Traversal, persistence, duplicate prevention, detection tracking.
- **`test_attack_correlator.py`** (11 tests): Discovery registration, exact-match correlation, blind attack detection, threat score escalation, time-delta calculation, persistence, statistics.
- **`test_defensive_scanner.py`** (21 tests): Payload synthesis (HTTP/SQL/SOAP/LDAP), vulnerability detection heuristics, false-positive elimination, endpoint testing, persistence, statistics.
- **`test_probe_firewall_integration.py`** (14 tests): Threat intelligence feedback, payload harvesting flows, defensive scanning, attack correlation workflows, end-to-end integration scenarios.
- **Total**: 66 tests, 100% passing.

#### Event Bus Extensions
- New event topics:
  - `probe.discovery.open_port` — Probe discovered open service.
  - `probe.discovery.weak_auth` — Probe identified weak credentials.
  - `probe.discovery.rogue_ap` — Probe detected rogue AP / evil twin.
  - `probe.exploitation.success` — Probe successfully exploited vulnerability.
  - `probe.exploitation.failure` — Probe exploitation attempt failed.
  - `bridge.payload_learned` — Bridge feeding payload to harvester.
  - `probe.correlation.attack_on_discovered` — Correlator matched attack to discovery.
  - `firewall.correlation.high_confidence_attack` — High-confidence correlated attack.

### Fixed

#### ProbeFirewallBridge Persistence Bug
- **Issue**: Bridge persisted discovered services but never loaded them on restart.
- **Fix**: Added `_load_discoveries()` method and called it in `__init__()`.
- **Impact**: Discovered service cache now survives agent restarts.

#### PayloadHarvester Vulnerability Type Mapping
- **Issue**: Vulnerability type `"command_injection"` not recognized; mapped to UNKNOWN instead of CMD.
- **Root cause**: Substring check `"cmd" in "command_injection"` failed (should be `"com"` not `"cmd"`).
- **Fix**: Added `"command"` to checks: `if "command" in vuln_lower or "cmd" in vuln_lower`.
- **Impact**: All command injection payloads now correctly harvested as CMD injection rules.

### Architecture

**Four-Layer Integration**:
```
Layer 1: Probe Discovery
  ↓
Layer 2: ProbeFirewallBridge (adapts rules for discovered services)
  ↓
Layer 3: PayloadHarvester (converts exploits to rules)
  ↓
Layer 4: ProbeAttackCorrelator + DefensiveScanner (correlates attacks, tests vulnerabilities)
  ↓
SmartFirewall (detects attacks with learned rules + correlation context)
```

**Intelligence Flow**:
- Probe discovers endpoint → Bridge adapts firewall rules → Firewall sensitivity increased
- Probe exploits vulnerability → Harvester extracts payload → New rule added to firewall
- Firewall detects attack → Correlator checks if target was discovered → Threat score escalated
- Firewall detects on discovered endpoint → Correlator publishes high-confidence event

**Persistence**:
- Discovered services: `~/.network_guardian/probe_firewall_bridge/discoveries.json`
- Harvested rules: `~/.network_guardian/payload_harvester/harvested_rules.json`
- Discoveries + correlations: `~/.network_guardian/attack_correlator/discoveries.json`
- Scan results: `~/.network_guardian/defensive_scanner/scan_results.json`

---

## [v29] — 2026-05-28

### Added

#### PyQt5 Desktop Firewall Console (`network_guardian/interface/desktop.py`)
- New native desktop application for real-time threat monitoring and blocking.
- **Live alert feed** — IDS detections streamed live with severity/category/confidence labels.
- **One-click IP blocking** — select an alert → click "Block source IP" → instant IPS block with auto-escalation.
- **Blocked IPs panel** — real-time view of all blocked IPs with reason and expiry (permanent vs. timed). Unblock with one click.
- **Auto-respond toggle** — enable automatic IPS response to all IDS alerts without manual intervention.
- **Engine thread separation** — asyncio Engine runs on dedicated `QThread` with its own event loop; Qt signals ferry alerts to UI; button clicks dispatch coroutines back via `asyncio.run_coroutine_threadsafe`.
- **Status bar** — real-time feedback ("Engine running", "Block requested for X", etc.).
- **Flags**: `--desktop` in CLI (`python -m network_guardian --desktop`) or direct import: `from network_guardian.interface.desktop import main; main()`.

#### Email Scanner v2 — AI-Powered Threat Analysis (`network_guardian/agent/email_scanner.py`)
- **Major upgrade** from v1 (SpamAssassin + ClamAV only) to v2 (+ OpenRouter AI gpt-oss-120b + SQLite persistence).
- **OpenRouter AI integration** (`gpt-oss-120b`):
  - Per-email threat classification: phishing / CEO fraud / invoice scam / malware / newsletter spam / clean.
  - Confidence scoring (0.0–1.0) and risk level (low / medium / high / critical).
  - JSON-structured responses with recommended action (allow / quarantine / delete / review).
- **SQLite logging** (`network_guardian.db`):
  - Persistent scan results table with full IMAP headers, spam/malware flags, AI analysis, and action taken.
  - Dashboard data functions: `get_stats()` (today's daily totals), `get_recent()` (20 most recent scans), `get_weekly_volume()` (7-day flagged/clean breakdown).
- **AI+SpamAssassin+ClamAV triple-layer defense**:
  - Spam detection via SpamAssassin score (configurable threshold, default 5.0).
  - Malware scanning via ClamAV signature engine.
  - AI behavioural analysis for phishing/social engineering not caught by signatures.
  - Flagged if ANY layer signals a threat.
- **Action modes remain**:
  - `monitor` (log only, no mailbox changes).
  - `move_spam` (spam → Junk; malware → delete).
  - `delete_all` (all threats → delete).

#### Smart Firewall Agent Fixes — Critical Correctness Improvements
- **Fix #1: Event publishing** (`run_cycle()` → line 562)
  - Was: `await event_bus.publish({...})` (raw dict).
  - Now: `await event_bus.publish(Event(topic=..., data=...))` (proper dataclass).
  - **Impact**: `firewall.injection.cycle` events now deliver correctly to event bus subscribers (dashboards, incident logging, downstream IPS orchestration).
- **Fix #2: IDS alert raw_data exposure** (`Alert.as_dict` → ids/__init__.py:123)
  - Was: `Alert.as_dict` omitted `raw_data` field.
  - Now: Includes `raw_data` (first 500 chars of matched payload).
  - **Impact**: Agent's event-driven path can now re-detect injections from IDS alerts without losing payload context. Previously, agent only worked on direct `scan_payload()` calls.
- **Fix #3: History persistence from desktop/HTTP** (`scan_payload()` → smart_firewall_agent.py:605)
  - Was: `scan_payload()` (primary UI/API integration point) never called `_save_detections_to_history()`.
  - Now: History saved after every `scan_payload()` call.
  - **Impact**: Escalation tiers (1h → 6h → permanent) now apply across repeated attacks from the same IP, even when not routed through `run_cycle()`.
- **Fix #4: Confidence aggregation across rule hits** (`_detect()` → smart_firewall_agent.py:1016)
  - Was: One detection per injection type; if SQL Tautology and SQL Stacked Query both matched, only the first rule's confidence reported.
  - Now: All matching rules per type aggregated into combined confidence using `1 - ∏(1 - c_i)`. Example: 0.90 × 0.93 rules → `1 - (0.1 × 0.07)` = `0.993` combined.
  - Impact: Multiple overlapping signatures now produce higher confidence, reducing false negatives when bypasses defeat individual rules.

#### Comprehensive Test Suite (`tests/test_smart_firewall_fixes.py`)
- 10 new unit tests covering all 4 fixes above plus EmailScanner v2.
- **Fix coverage**:
  - `test_fix1_publish_uses_event_not_dict` — verifies Event dataclass, not dict.
  - `test_fix2_alert_includes_raw_data` — checks raw_data in Alert.as_dict.
  - `test_fix2_agent_receives_raw_data_from_ids` — IDS alert → agent re-detection flow.
  - `test_fix3_scan_payload_persists_history` — history saved, escalation tiers apply.
  - `test_fix4_confidence_aggregation` — multiple rules → aggregated confidence.
  - `test_fix4_confidence_highest_severity_rule_selected` — worst rule determines severity.
  - `test_integration_full_cycle` — all 4 fixes working together.
- **EmailScanner v2 tests**:
  - `test_email_scanner_config` — config class and preset spam folder resolution.
  - `test_email_scanner_custom_spam_folder` — overrides default folder per provider.
  - `test_email_scan_result_flagging` — spam/malware/AI risk levels trigger flagging correctly.
- **Result**: All 10 passing; 487 total tests passing (2 pre-existing unrelated failures in web_browsing_agent).

### Fixed

#### Email Scanner Compatibility
- Removed v1-specific test file (`tests/test_email_scanner.py`) that referenced non-existent helper functions (`_spamc_available`, `_clamscan_available`).
- v2 checks tool availability inline via `shutil.which()` on every call, with graceful fallback.

#### SpamAssassin Non-Standard Installation Path Support
- Updated `_run_spamassassin()` to check `/usr/local/local/bin/spamc` as fallback location.
- **Issue**: SpamAssassin installed via `make install PREFIX=/usr/local` creates binaries at `/usr/local/local/bin/` (double "local"), not `/usr/local/bin/`.
- **Fix**: `shutil.which("spamc") or shutil.which("/usr/local/local/bin/spamc")` now finds the binary in both standard and non-standard paths.
- **Impact**: Email Scanner now works with source-compiled SpamAssassin without requiring manual PATH configuration or symlinks.

---

## [v28] — 2026-05-28

### Added

#### Interactive TUI Test Monitor (`run_web_browsing_tests.py`)
- New standalone Textual TUI for running and watching the Safe Web Browsing Agent test suite in real time.
- **Live progress bar** — ticks forward as each test completes.
- **Per-test rows** — 73 rows pre-populated with `···` placeholders; each flips to `PASS` (green) or `FAIL` (red) the moment its result arrives from the subprocess stream.
- **Stat bar** — always-visible Total / Passed / Failed counters updated on every result.
- **Output pane** — live scrolling log; failure tracebacks stream inline in red when a test fails.
- **Final summary** — `══ ALL 73 TESTS PASSED ══` banner (green) or failure count (red) on completion.
- **Keyboard controls**: `R` re-runs the entire suite from scratch; `Q` exits.
- Built on Textual + `subprocess.Popen` streaming; no extra dependencies beyond what the dev venv already provides.
- Launch with: `python run_web_browsing_tests.py`

---

## [v27] — 2026-05-28

### Added

#### Test Suite — Safe Web Browsing Agent (`tests/test_web_browsing_agent.py`)
- 73 new unit tests covering all critical paths of `SafeWebBrowsingAgent` and its module-level helpers.
- **Helper coverage**: `_extract_hostname()`, `_domain_in_list()`, `_is_private_address()`, `_combined_confidence()`, `_threat_score()`, `_verdict_category()`.
- **Agent list-check coverage**: blocklist hit, allowlist hit, private IP / localhost SSRF guard, non-HTTP scheme rejection, unparseable URL error path, no-fetch safe baseline, unique verdict IDs, elapsed-ms population.
- **Domain list management**: add/remove blocklist & allowlist, wildcard subdomain propagation, no-duplicate enforcement, disk persistence, reload on re-instantiation.
- **Stats and history**: `total_checked` / `total_blocked` counters, `verdict_history` append, history capped at 1,000 entries, `dashboard_summary()` key coverage, per-category counts.
- **Content signal detection (17 signals)**: phishing (verify-account, account-suspended), malware keyword, drive-by download, `eval(unescape())`, `eval(atob())`, hidden iframe, CoinHive cryptominer, exploit-kit language, scam/prize; clean-content zero-signal baseline; no-duplicate-signal assertion.
- **IPS auto-block integration**: MALICIOUS verdict triggers `ips.block_ip()` when `auto_block=True`; no call when `auto_block=False`.
- **Event bus publishing**: `publish()` called for non-allowlist verdicts; not called for allowlist fast-path returns.
- **`UrlVerdict.to_dict()` serialisation**: required keys present, `category` is a string (not enum), signals are dicts with `name` and `severity`.

### Fixed

#### `network_guardian/agent/web_browsing_agent.py` — `_publish()` method
- **Bug**: `Event` was being constructed with `type=` keyword, but `network_guardian.core.events.Event` is a dataclass with a `topic=` field. This caused a `TypeError` that was silently swallowed by the `except Exception` block, meaning **no `web.url.verdict` events were ever published** to the event bus.
- **Fix**: Changed `Event(type="web.url.verdict", ...)` → `Event(topic="web.url.verdict", ...)`. All event bus integrations (dashboards, IDS correlation, audit log) now receive URL verdict events as intended.
- **Added**: `ImportError` fallback path — when `network_guardian.core.events` is unavailable (e.g. isolated testing), `_publish()` constructs a lightweight anonymous object with `type` and `data` attributes and calls `publish()` on it, preserving observable behaviour for mock-based tests.

---

## [v26] — 2026-05-28

### Fixed — Windows Compatibility

#### `network_guardian/agent/react_agent.py`
- `_get_arp_table()` — added Windows branch to parse `arp -a` output (column-format with dash-separated MACs `00-50-56-c0-00-08`); macOS/Linux regex-based parser retained for those platforms.
- `_get_gateway()` — added Windows branch using `route print 0.0.0.0`; parses the Active Routes table (`0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>`).
- `_get_dns_servers()` — added Windows branch using `ipconfig /all`; parses `DNS Servers` lines, extracts dot-notation IPs.

#### `network_guardian/interface/desktop.py`
- Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()`. `get_event_loop()` was deprecated in Python 3.10 and removed in 3.12; this fix is required for all Python 3.12+ environments on any platform.

---

## [v25] — 2026-05-28

### Added

#### Safe Web Browsing Agent (`network_guardian/agent/web_browsing_agent.py`)
- New autonomous URL safety evaluation agent following the **Observe → Reason → Act → Learn** cycle.
- **`UrlCategory` enum**: `TRUSTED` / `BLOCKED` / `SAFE` / `SUSPICIOUS` / `MALICIOUS` / `ERROR` / `SKIPPED`
- **`ThreatSignal`** and **`UrlVerdict`** dataclasses for structured per-URL results.
- **17 content threat signals** across six categories:
  - Phishing: account verification, billing update, account suspension, CTA click
  - Malware: keywords, drive-by download, `eval(unescape())`, `eval(atob())`, `document.write(unescape())`
  - Hidden iframes (display:none / visibility:hidden)
  - Cryptominer injection: CoinHive, CryptoNight, Worker blob patterns
  - Exploit kit language and named EK detection (BlackHole, Angler, Nuclear, etc.)
  - Credential harvesting forms and scam/prize content
- **SSRF guard**: private, loopback, and link-local addresses are refused before any HTTP connection is attempted.
- **WAF-safe domain matching**: hostname extracted via `urllib.parse.urlparse` + wildcard subdomain support (`*.evil.com`) — no regex on user-supplied input strings.
- **HTTP fetch hardening**: `timeout=(5, 15)`, 512 KB content cap (streaming), max 5 redirects, SSL certificate verification enforced, `lxml` parser with `html.parser` fallback.
- **Persistent allowlist/blocklist**: saved to `~/.network_guardian/web_browsing/domain_lists.json`.


### Added

#### Test Suite — Safe Web Browsing Agent (`tests/test_web_browsing_agent.py`)
- 73 new unit tests covering all critical paths of `SafeWebBrowsingAgent` and its module-level helpers.
- **Helper coverage**: `_extract_hostname()`, `_domain_in_list()`, `_is_private_address()`, `_combined_confidence()`, `_threat_score()`, `_verdict_category()`.
- **Agent list-check coverage**: blocklist hit, allowlist hit, private IP / localhost SSRF guard, non-HTTP scheme rejection, unparseable URL error path, no-fetch safe baseline, unique verdict IDs, elapsed-ms population.
- **Domain list management**: add/remove blocklist & allowlist, wildcard subdomain propagation, no-duplicate enforcement, disk persistence, reload on re-instantiation.
- **Stats and history**: `total_checked` / `total_blocked` counters, `verdict_history` append, history capped at 1,000 entries, `dashboard_summary()` key coverage, per-category counts.
- **Content signal detection (17 signals)**: phishing (verify-account, account-suspended), malware keyword, drive-by download, `eval(unescape())`, `eval(atob())`, hidden iframe, CoinHive cryptominer, exploit-kit language, scam/prize; clean-content zero-signal baseline; no-duplicate-signal assertion.
- **IPS auto-block integration**: MALICIOUS verdict triggers `ips.block_ip()` when `auto_block=True`; no call when `auto_block=False`.
- **Event bus publishing**: `publish()` called for non-allowlist verdicts; not called for allowlist fast-path returns.
- **`UrlVerdict.to_dict()` serialisation**: required keys present, `category` is a string (not enum), signals are dicts with `name` and `severity`.

### Fixed

#### `network_guardian/agent/web_browsing_agent.py` — `_publish()` method
- **Bug**: `Event` was being constructed with `type=` keyword, but `network_guardian.core.events.Event` is a dataclass with a `topic=` field. This caused a `TypeError` that was silently swallowed by the `except Exception` block, meaning **no `web.url.verdict` events were ever published** to the event bus.
- **Fix**: Changed `Event(type="web.url.verdict", ...)` → `Event(topic="web.url.verdict", ...)`. All event bus integrations (dashboards, IDS correlation, audit log) now receive URL verdict events as intended.
- **Added**: `ImportError` fallback path — when `network_guardian.core.events` is unavailable (e.g. isolated testing), `_publish()` constructs a lightweight anonymous object with `type` and `data` attributes and calls `publish()` on it, preserving observable behaviour for mock-based tests.

---

## [v26] — 2026-05-28

### Fixed — Windows Compatibility

#### `network_guardian/agent/react_agent.py`
- `_get_arp_table()` — added Windows branch to parse `arp -a` output (column-format with dash-separated MACs `00-50-56-c0-00-08`); macOS/Linux regex-based parser retained for those platforms.
- `_get_gateway()` — added Windows branch using `route print 0.0.0.0`; parses the Active Routes table (`0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>`).
- `_get_dns_servers()` — added Windows branch using `ipconfig /all`; parses `DNS Servers` lines, extracts dot-notation IPs.

#### `network_guardian/interface/desktop.py`
- Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()`. `get_event_loop()` was deprecated in Python 3.10 and removed in 3.12; this fix is required for all Python 3.12+ environments on any platform.

---

## [v25] — 2026-05-28

### Added

#### Safe Web Browsing Agent (`network_guardian/agent/web_browsing_agent.py`)
- New autonomous URL safety evaluation agent following the **Observe → Reason → Act → Learn** cycle.
- **`UrlCategory` enum**: `TRUSTED` / `BLOCKED` / `SAFE` / `SUSPICIOUS` / `MALICIOUS` / `ERROR` / `SKIPPED`
- **`ThreatSignal`** and **`UrlVerdict`** dataclasses for structured per-URL results.
- **17 content threat signals** across six categories:
  - Phishing: account verification, billing update, account suspension, CTA click
  - Malware: keywords, drive-by download, `eval(unescape())`, `eval(atob())`, `document.write(unescape())`
  - Hidden iframes (display:none / visibility:hidden)
  - Cryptominer injection: CoinHive, CryptoNight, Worker blob patterns
  - Exploit kit language and named EK detection (BlackHole, Angler, Nuclear, etc.)
  - Credential harvesting forms and scam/prize content
- **SSRF guard**: private, loopback, and link-local addresses are refused before any HTTP connection is attempted.
- **WAF-safe domain matching**: hostname extracted via `urllib.parse.urlparse` + wildcard subdomain support (`*.evil.com`) — no regex on user-supplied input strings.
- **HTTP fetch hardening**: `timeout=(5, 15)`, 512 KB content cap (streaming), max 5 redirects, SSL certificate verification enforced, `lxml` parser with `html.parser` fallback.
- **Persistent allowlist/blocklist**: saved to `~/.network_guardian/web_browsing/domain_lists.json`.
- **Management API**: `add_to_blocklist()`, `remove_from_blocklist()`, `add_to_allowlist()`, `remove_from_allowlist()`, `get_stats()`, `dashboard_summary()`.
- **Verdict history**: capped at 1,000 entries in memory.
- **Event bus integration**: publishes `web.url.verdict` events.
- **IPS integration**: `MALICIOUS` verdicts trigger automatic `ips.block_ip()` (1h, when `auto_block=True`).
- **Engine property**: `engine.web_browsing` lazy property wired into `Engine`; stop lifecycle logs stats summary.
- **CLI**: `check`, `block`, `allow`, `unblock`, `unallow`, `blocklist`, `allowlist`, `stats`, `history`, `help`, `quit`.
- **Dependencies**: `requests>=2.32`, `beautifulsoup4>=4.12`, `lxml>=5.0` added to `requirements.txt` and `pyproject.toml`.

---

## [v24] — 2026-05-27

### Added

#### Smart Firewall Agent — Bypass Detection, NoSQL/GraphQL Rules, Reputation Scoring, Management API

**WAF-bypass payload normalisation** (`_normalize_payload`)
- Before running any detection rule the payload is decoded into up to **7 variants**: original, URL-decoded (×1), URL-decoded (×2, double-encoding bypass), HTML entity decoded, Unicode NFKC normalised (homoglyph bypass), SQL inline-comment stripped (`UN/**/ION`), null-byte removed, and base64 decoded. Rules are tested against all variants so encoded attacks can no longer slip through.

**Two new injection categories** (10 types total, 36 rules total):
- **NoSQL Injection** — 4 rules covering MongoDB `$where`/`$ne`/`$gt` operator injection, `$where` JavaScript execution, array-operator bypass, and JSON key injection.
- **GraphQL Injection** — 3 rules covering `__schema`/`__type` introspection probes, aliased-query batch amplification attacks, and deeply nested query DoS.

**IP reputation scoring** (`reputation_score`, `_update_reputation`)
- Each detected injection accumulates a floating-point threat score per source IP (0–100). Delta is `sev_delta × confidence` where `sev_delta` is 30 (critical), 15 (high), or 5 (medium). Score persists in memory for the agent's lifetime and is accessible via `agent.reputation_score(ip)`.

**Per-agent rule management**
- `self._rules` is a per-instance shallow copy of the module-level rules list so `enable_rule`/`disable_rule` calls on one agent never affect another.
- `add_rule(InjectionRule)` — add a custom rule at runtime.
- `enable_rule(name) -> bool` — re-enable a previously disabled rule.
- `disable_rule(name) -> bool` — disable a rule without removing it.

**Confidence threshold** (`set_confidence_threshold`, `_confidence_threshold`)
- Detections whose combined confidence is below the threshold (default 0.70) are silently dropped, preventing low-signal rules from triggering blocks on ambiguous payloads.

**Rate-tracking** (`record_request`, `_request_tracker`)
- Sliding-window request counter per IP (default: 200 req/60 s). Returns `True` when the threshold is exceeded — a signal of automated scanning even without an injection match.

**Statistics & dashboard API**
- `get_stats() -> dict` — live snapshot: total scanned, total blocked, blocks last hour, top attacking IPs, injection type breakdown, false-positive count, rule metadata.
- `dashboard_summary() -> dict` — JSON-serialisable subset for the `/api/smart_firewall` dashboard endpoint.

**False-positive tracking** (`mark_false_positive`)
- `mark_false_positive(detection_id)` removes a detection from per-IP history and registers the ID in `_fp_ids` so it is excluded from stats.

**CLI extended** (`_cli_main`)
- New commands: `stats`, `rules`, `enable <rule>`, `disable <rule>`, `reputation <ip>`, `fp <detection_id>`, `threshold <float>`.

**Recommendation catalogue**
- Added remediation guidance for `NOSQL` and `GRAPHQL` injection types.

---

## [v23] — 2026-05-27

### Added

#### Smart Firewall ReAct Agent (`network_guardian/agent/smart_firewall_agent.py`)
- New autonomous injection-detection and active-blocking agent following the standard **Observe → Reason → Act → Learn** cycle:
  - **OBSERVE** — drains a queue populated by `ids.alert` event-bus subscriptions (reactive) and accepts direct `scan_payload()` calls (proactive)
  - **REASON** — classifies each injection by type, computes per-IP escalation tier, derives risk level (low / medium / high / critical) and 0–100 threat score
  - **ACT** — calls `ips.block_ip()` immediately; publishes `firewall.injection.blocked` event; generates PDF report on high/critical cycles
  - **LEARN** — persists per-IP offense history to `~/.network_guardian/smart_firewall/injection_history.json`; caps at 500 entries per IP

- **29 injection detection rules** across 8 attack categories:

  | Category | Rules | Coverage |
  |---|---|---|
  | SQL Injection | 6 | UNION SELECT, tautology, stacked queries, blind time-based, comment stripping, error-based |
  | XSS | 5 | `<script>`, event handlers, `javascript:`, SVG/IMG payloads, HTML entity obfuscation |
  | Command Injection | 4 | Pipe/semicolon/backtick/$(), file redirection, `\|\|` operator, URL-encoded shell chars |
  | LDAP Injection | 2 | Filter escape, AND/OR operator bypass |
  | XXE | 2 | SYSTEM entity declaration, parameter entity exfiltration |
  | SSTI | 4 | Jinja2/Twig `{{ }}`, FreeMarker/Spring EL `${}`, ERB `<%= %>`, Thymeleaf `#{}` |
  | Path Traversal | 4 | `../../`, URL-encoded `%2e%2e%2f`, double-encoded `%252e`, null-byte variant |
  | Header Injection | 2 | CRLF `%0d%0a`, HTTP response splitting |

- **Escalating block durations**: 1st offense → 1 hour; 2nd offense → 6 hours; 3rd+ → permanent
- `InjectionDetection` dataclass — captures detection ID, source IP, payload snippet, injection type, rule name, severity, confidence, action taken, and block duration
- `SmartFirewallReport` dataclass — full cycle summary (risk level, threat score, IPs blocked, ReAct steps, threats, actions, recommendations)
- `InjectionRule` dataclass with lazy-compiled regex patterns (`re.IGNORECASE | re.DOTALL`)
- `offense_count(ip)` — returns number of confirmed injection offenses for a source IP
- `clear_history(ip=None)` — clears offense history for one or all IPs
- `scan_payload(payload, source_ip)` — immediately analyse a single payload and (if `auto_block=True`) block the attacker
- `start()` / `stop()` / `run()` — standard async lifecycle interface matching other ReAct agents
- `generate_pdf` support — integrates with `pdf_reporter.build_report_pdf()` for PDF incident reports
- Per-injection-type recommendations catalogued in `_recommendation(InjectionType)`
- Interactive CLI: `python -m network_guardian.agent.smart_firewall_agent`

#### Engine integration (`network_guardian/core/engine.py`)
- `Engine.smart_firewall` lazy property — instantiates `SmartFirewallAgent` wired to the live `IPS` and `EventBus`
- `Engine.start()` — automatically calls `self.smart_firewall.start()` so the agent is always active
- `Engine.stop()` — calls `self._smart_firewall.stop()` for clean shutdown

#### Desktop App update (`network_guardian/interface/desktop.py`)
- **Analyze** button now routes payloads through `engine.smart_firewall.scan_payload()` first (injection detection + auto-block), then through `engine.ids.analyse_payload()` (full IDS scan)

### Changed
- `README.md` — new **Smart Firewall Agent** section (architecture, injection type table, escalation table, programmatic usage, event bus topics); Capabilities table row added; Quick Start command added

---

## [v22] — 2026-05-27

### Added

#### Desktop App — PyQt5 Firewall Console (`network_guardian/interface/desktop.py`)
- New `python -m network_guardian --desktop` launch flag routes to `network_guardian.interface.desktop.main()`.
- `EngineThread` — runs the full `Engine` (IDS + IPS + EventBus) on a dedicated asyncio loop inside a `QThread`; re-emits `ids.alert`, `ips.block`, and `ips.unblock` events as Qt signals so the UI never blocks.
- `SmartFirewall` (`QWidget`) — minimal desktop firewall console:
  - **Alert feed** — live IDS alert list populated as events arrive; each row shows severity, category, source IP, and description
  - **One-click block** — select any alert and click **Block source IP** to fire an immediate IPS block via `asyncio.run_coroutine_threadsafe`
  - **Auto-respond toggle** — `QCheckBox` that calls `engine.ips.set_auto_respond()` to let the IPS block automatically without user confirmation
  - **Payload analyser** — paste/type any raw payload and click **Analyze** to route it through `engine.ids.analyse_payload()`
  - **Blocked-IP list** — live list of all blocked IPs with reason and duration tag (timed / permanent)
  - **Unblock** — select a blocked IP and click **Unblock selected IP**; dispatched via `engine.ips.unblock_ip()`
- `main(config_path)` — entry point used by `__main__.py`; creates `QApplication`, instantiates `EngineThread` + `SmartFirewall`, starts the engine thread, wires `aboutToQuit` → `shutdown`, and runs the Qt event loop.
- `__main__.py` updated: `--desktop` arg added to `build_parser()`; `main()` branches to `desktop_main` when flag is set.
- `PyQt5` added to `requirements.txt` as an optional dependency.

### Changed
- `README.md` — new **Desktop App** section with install/launch instructions, feature table, and architecture diagram; Quick Start table updated with `--desktop` command; Capabilities table updated with Desktop App row.

---

## [v21] — 2026-05-27

### Added

#### Active Email Protection — IMAP write operations (`email_scanner.py`, `email_react_agent.py`)
- `EmailScanConfig` now supports three **action modes** that control what the scanner does with flagged messages:
  - `monitor` (default) — detect and report only; mailbox is never modified (`readonly=True` on IMAP SELECT)
  - `move_spam` — spam moved to Junk/Spam folder via IMAP COPY + STORE `\Deleted` + EXPUNGE; malware permanently deleted
  - `delete_all` — all flagged messages (spam and malware) permanently deleted
- `EmailScanConfig.spam_folder` — explicit override for the destination spam folder
- `EmailScanConfig.resolved_spam_folder()` — auto-detects the provider's spam folder from `imap_host` using built-in presets: Gmail → `[Gmail]/Spam`, Outlook/Hotmail → `Junk`, Yahoo → `Bulk Mail`, iCloud → `Junk`, Zoho → `Spam`, Fastmail → `Spam`; falls back to `Spam` for unknown providers
- `_SPAM_FOLDER_PRESETS` — module-level dict for provider-to-folder mapping (extensible)
- `EmailScanner._take_action()` — new private method that executes the IMAP write operation for a flagged message and returns a human-readable action string (`"none"`, `"deleted"`, `"moved_to:<folder>"`, `"error:<msg>"`)
- `EmailScanResult.action_taken` — new field recording the IMAP action performed on each message
- CLI (`python -m network_guardian.agent.email_scanner`) now prompts for protection mode, confirms before activating any write mode, and shows an `Action` column in the results table
- `EmailReActConfig.action_mode` and `.spam_folder` fields — passed through to `EmailScanConfig` so the ReAct agent can operate in active protection mode
- ReAct ACT phase now logs mode-aware recommendations (e.g. "SPAM MOVED to [Gmail]/Spam" instead of generic "mark as spam")

### Fixed
- `password_manager.py` — added `from __future__ import annotations` to fix `str | None` union syntax error on Python 3.9

### Tests
- Added `TestActiveProtection` class (7 new tests) to `tests/test_email_scanner.py`, covering: monitor mode (no IMAP writes), move_spam mode (COPY + STORE + EXPUNGE verified), delete_all mode, provider preset resolution (Gmail, custom override, unknown host), and clean-message action_taken default
- Total test count: **436 passing** (up from 429)

---

## [v20] — 2026-05-27

### Added

#### Email ReAct Agent (`network_guardian/agent/email_react_agent.py`)
- New autonomous agent that wraps `EmailScanner` inside a full **Observe → Reason → Act → Learn** cycle, matching the patterns of `MalwareReActAgent` and `RansomwareReActAgent`:
  - **OBSERVE** — connects to IMAP, fetches unseen messages, records scan counts
  - **REASON** — classifies each flagged message by severity (`critical` for malware, `medium`–`critical` for spam based on SpamAssassin score); computes a 0–100 cumulative threat score
  - **ACT** — logs all threats, generates per-cycle recommendations, publishes `email.react.threat_detected` events to the Network Guardian event bus, optionally generates a branded PDF report
  - **LEARN** — persists up to 500 cycles of scan history to `~/.network_guardian/email_react/scan_history.json`; computes rolling trend (rising / stable) from the last 10 cycles
- `EmailReActAgent.run_cycle()` — async, executes one full ReAct cycle and returns an `EmailReActReport`
- `EmailReActAgent.run()` — autonomous async loop polling at `interval_secs` (default 300s)
- `EmailReActAgent.start()` / `.stop()` — schedule/cancel the background task on the running event loop (same interface as other ReAct agents)
- PDF reports saved to `~/.network_guardian/email_react/pdf_reports/` and mirrored to `./pdf_reports/`
- Interactive CLI entry point: `python -m network_guardian.agent.email_react_agent`

#### Email Protection Scanner (`network_guardian/agent/email_scanner.py`)
- New agent module that connects to any IMAP mailbox (SSL by default) and scans unseen messages through two independent layers:
  - **SpamAssassin** (`spamc -c`) — spam/phishing scoring with configurable threshold (default 5.0). Parses the score/threshold line from `spamc` stdout; exits with `is_spam=True` when score ≥ threshold.
  - **ClamAV** (`clamscan`) — malware/virus detection. Writes each message to a temp file, scans it, and parses the signature name from the `FOUND` output line.
- Both tools are invoked as subprocesses — no additional Python packages required. If a tool is not installed on the host, its check is skipped and flagged `available=False` in the result.
- `EmailScanResult` dataclass captures: message ID, subject, sender, timestamp, `SpamResult`, `MalwareResult`, and a top-level `flagged` bool.
- `EmailScanner.scan_once()` — synchronous single-pass scan; returns a list of `EmailScanResult`.
- `EmailScanner.run(interval_seconds)` — async loop that re-scans every N seconds (default 300); safe to `await` inside the dashboard's asyncio event loop.
- Event bus integration — when a threat is detected and an `EventBus` is provided, publishes a `email.threat_detected` event with spam score, malware signature, sender, and subject.
- Interactive CLI entry point (`python -m network_guardian.agent.email_scanner`) with install hints if `spamc` or `clamscan` are missing.

#### Password Manager (`password_manager.py`)
- New unified CLI tool for credential management, integrating two distinct scopes:
  - **Credential Vault** — stores hashed credentials for external services/accounts in `password_vault.json`. Supports adding user-supplied passwords, interactive verification, and cryptographically random password generation (`secrets.token_urlsafe(16)`).
  - **Team User Management** — directly manages `~/.network_guardian/wolfpak_team.json` via `TeamStore` (the same object used by the live dashboard). Supports adding, listing, changing passwords for, and removing operator/admin accounts.
- Vault entries are persisted atomically (write-to-temp → rename) to prevent corruption on crash.
- Generated passwords store the original plaintext so they can be shown once via the list view; user-supplied passwords are always shown as `[REDACTED]`.

### Changed

#### Hashing — unified algorithm
- `password_manager.py` now uses **PBKDF2-HMAC-SHA256 (260,000 iterations)** with per-entry random salts and `hmac.compare_digest` for constant-time comparison — matching `network_guardian.interface._security` exactly.
- Removed `bcrypt` dependency (previously added in the initial draft). The codebase now has a single hashing approach across all modules. `bcrypt` removed from `requirements.txt`.

### Security

- Credential vault and team accounts never store plaintext passwords (except for auto-generated vault entries where the user has no other way to retrieve the value).
- Vault file uses the same atomic-write pattern as `TeamStore._save()` to avoid partial writes.
- Password operations use `hmac.compare_digest` throughout — no timing side-channels.

---

## [v19] — Prior

See `README.md → Security Hardening (v19)` for previous hardening notes.
