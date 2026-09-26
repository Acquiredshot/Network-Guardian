# Wolf-Pak Platform — Three-Project Correlation Spec

**Status:** Draft v1.0 — describes the shared contracts and per-project changes needed for Network Guardian, MASK, and PakShield to interoperate as the Wolf-Pak roadmap intends.

**Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.**

---

## 1. The three projects, as they stand today

### 1.1 Network Guardian (`C:\Users\CodyC\Network Guardian\Network-Guardian\`)

**Owns:** network-layer detection and response. Packet analysis, flow monitoring, IDS/IPS signals, network anomaly detection, AI engine (Isolation Forest, One-Class SVM, ARIMA), J.A.R.V.I.S. terminal shell, web dashboard, SaaS multi-tenant control plane.

**Roadmap role:** Network Security Detection/Response — the leftmost top-row pillar.

**What exists for the lower layers (as of v1.0.0):**

| Layer | What NG already has | Gap |
|---|---|---|
| Event Fabric | Scaffolding: `wolf_pak_security/event_fabric/` with `EventEnvelope`, `EventBus`, `EventStorage` placeholder classes | No running bus; no ingestion from other apps |
| Security Graph | Scaffolding: `wolf_pak_security/security_graph/` with `GraphEntity`, `GraphRelationship`, `SecurityGraph` | No graph state; no edges from MASK/PAKSHIELD nodes |
| Threat Intel | Scaffolding: `wolf_pak_security/threat_intel/` with `IntelIngestor`, `IntelStore`, `IntelEnricher` | No feed ingestion; no IOC enrichment of NG detections |
| AI Security Orchestrator | Scaffolding: `ai_orchestrator/` with `DetectionPipeline`, `InvestigationSession`, `ResponsePlanner` | No orchestrated detection/investigation/response; JARVIS is keyword-based, not orchestrated |
| Policy Engine | Scaffolding: `policy_engine/` with `PolicyRule`, `Policy`, `PolicyEngine` | No policy evaluation connected to actions; NG has firewall rules but no formal policy engine |
| Action Gateway | Scaffolding: `action_gateway/` with `Action`, `ActionConnector`, `ActionGateway` | No structured action execution; NG has manual block-isolate APIs but no action gateway facade |

**Shared event schema already defined:** `wolf_pak_security/events.py` with `DetectionEvent`, `DetectionBatch`, `IntelEvent`, `AuditEvent` dataclasses.

---

### 1.2 MASK (`C:\Users\CodyC\MASK\`)

**Owns:** single-host system monitoring + LLM reasoning loop. C daemon (`maskd`) with: ring buffer (fixed-capacity event memory), tool gateway (sandboxed `fork`+`execvp`+`setrlimit`+`poll` command execution), IPC loopback server (`set_config` live config), LLM client, React dashboard bridge.

**Roadmap role:** Network/Asset Intelligence — the rightmost top-row pillar.

**What MASK already has that the roadmap needs (assets, not gaps):**

- Bounded memory (ring buffer overwrite semantics — exactly right for a host sensor that can't be memory-flooded)
- Sandboxed execution (`fork`+`execvp`+`setrlimit`+`poll` timeout — right foundation for a response action gateway)
- Non-blocking reactor (LLM on detached worker thread; reactor never blocks on I/O)
- Live config (`set_config` proves runtime reconfiguration without restart)
- Tool manifest (clean way to tell the LLM what's available; adding tools extends the LLM's capability surface)
- Web dashboard (becomes the investigation UI)

**What MASK currently emits:** `sysinfo` samples as bare JSON (`{"load1":..., "mem_total_kb":...}`) with no envelope, no asset ID, no severity, no category. The ring buffer stores entries with `role` + `text` + `timestamp_ms` but never exports them.

See `MASK\ROADMAP_CORRELATION.md` for MASK's own detailed internal mapping — this spec builds on it.

---

### 1.3 PakShield (`C:\Users\CodyC\PakShield\`)

**Owns (the real engine — `core.py`):** Identity, Access & Privilege Intelligence. Per-tenant data model: Tenant → Identity (User / ServiceAccount / Group / Role) → Device → Application → Resource → Permission → Policy → Credential → Session → AccessEvent → RiskEvent → Finding → Violation → Remediation. SQLite-backed (`pakshield.db`). Policies include access_control, mfa, device_posture, password, data_classification, session, dangerous_action, anomaly, retention, custom.

**Owns (the demo app — `app.py` + `VendorPayloadVerification.py`):** A separate procurement/vendor demo (CRM + marketplace + Ed25519 signature verification + crypto engine + risk scoring). This is NOT the identity engine and is out of scope for the correlation — it's a presentation demo.

**Roadmap role:** Identity Risk & Access — the middle top-row pillar.

**What PakShield already has that the roadmap needs:**

- Rich identity model (users, service accounts, groups, roles, permissions)
- Device model with posture scores, compliance status, MFA capability
- Policy engine with conditions (JSON/CEL expressions), effects (allow/deny/audit/remediate), priorities
- Risk events with severity, risk_score, source, indicators
- Access events with policy_decisions (JSON array of policy evaluations)
- Findings and violations with remediation tracking
- Per-tenant isolation (all tables have `tenant_id`)

**What PakShield lacks for the correlation:**

- No asset ID scheme that matches MASK's host ID or NG's network-flow IDs
- No outbound event export (risk events stay in `pakshield.db`)
- No integration contract with MASK or NG (no API, no protocol, no shared event format)
- No host-context queries (can't ask "who's logged in on host X" because PakShield doesn't know which device is which host in MASK's sense)

---

## 2. Shared contracts (the correlation surface)

These are the things all three projects must agree on. They are the foundation; everything else builds on them.

### 2.1 Common event envelope

Every security-relevant observation that any of the three apps produces must be wrappable in a common envelope so the Event Fabric can ingest it without per-app knowledge.

**Proposed envelope (JSON):**

```json
{
  "timestamp_ms": 1761900000000,
  "asset_id": "host-codyc-wkstn-01",
  "source": "MASK",
  "source_version": "0.1.0",
  "event_type": "process_observation",
  "severity": "medium",
  "category": "process",
  "description": "Unexpected process 'xmrig' running under user 'marcus'",
  "payload": {
    "...": "..."
  }
}
```

**Field semantics:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `timestamp_ms` | integer (epoch ms) | yes | When the observation was made (UTC) |
| `asset_id` | string | yes | Stable ID of the asset this observation is about (see §2.2) |
| `source` | string | yes | Which app produced it: `NETWORK_GUARDIAN`, `MASK`, `PAKSHIELD` |
| `source_version` | string | no | Version of the producing app (for debugging) |
| `event_type` | string | yes | Specific observation type (e.g. `process_observation`, `network_flow`, `risk_scored`, `access_denied`) |
| `severity` | string | yes | One of `info`, `low`, `medium`, `high`, `critical` |
| `category` | string | yes | High-level taxonomy: `process`, `network`, `auth`, `identity`, `file`, `device`, `policy`, `threat` |
| `description` | string | no | Human-readable summary |
| `payload` | object | yes | Structured data specific to the event type; consumers who don't understand a type can still store/index the envelope |

**Mapping to existing schemas:**

- NG's `DetectionEvent` (event_id, source, timestamp, severity, category, description, context) → envelope with `event_id` as a separate field, `context` becoming `payload`. NG events already carry most fields.
- MASK's ring buffer entries (role, text, timestamp_ms) → need asset_id, source, event_type, severity, category, payload wrapping the existing `text`/JSON.
- PakShield's `RiskEvent` (id, tenant_id, identity_id, device_id, source, severity, risk_score, title, description, indicators, status, created_at) → envelope with `event_type` = `risk_scored`, `payload` carrying the risk_score, indicators, related identity/device. PakShield's `AccessEvent` (id, tenant_id, identity_id, device_id, action, outcome, source_ip, policy_decisions, context, recorded_at) → envelope with `event_type` = `access_event`, `payload` carrying action, outcome, policy_decisions.

**Decision needed:** Do we extend NG's existing `DetectionEvent`/`IntelEvent`/`AuditEvent` dataclasses to be the canonical envelope, or define a new `WolfPakEnvelope` that all three serialize to? The cleanest path is to make the envelope a thin wrapper and let each app keep its native types internally, serializing to the envelope at the export boundary.

### 2.2 Asset ID scheme

The Security Graph needs stable node keys. An asset is anything that can be observed or acted upon: a host, a network device, a user identity, a service account, a container, a cloud VM.

**Proposed scheme:**

```
<asset-type>-<scope>-<stable-identifier>
```

Examples:

- `host-codyc-wkstn-01` — a host (MASK's machine), scope = local network, identifier = hostname or machine ID
- `device-wks-lisa-01` — a device (PakShield's device table), scope = tenant, identifier = PakShield's device ID
- `identity-marcus-oneill` — a user identity (PakShield's identity), scope = tenant, identifier = PakShield's identity ID
- `flow-10.1.1.50->10.2.0.10:443` — a network flow (NG's observation), scope = network, identifier = src/dst/port tuple
- `service-ci-cd-pipeline` — a service account (PakShield), scope = tenant

**Rules:**

1. **MASK assigns its host asset ID** via `set_config` or env var (`MASK_ASSET_ID`). One line of code. This is the host's stable identity in the Security Graph. (MASK's ROADMAP_CORRELATION.md §6 step 1.)
2. **PakShield's device IDs** become asset IDs with a `device-` prefix when they need to be referenced outside PakShield (e.g. in the Security Graph, or by MASK when querying host context).
3. **PakShield's identity IDs** become asset IDs with an `identity-` prefix when referenced outside PakShield.
4. **NG generates flow asset IDs** from the src/dst/port tuple when it needs to reference a flow in the Security Graph.
5. **Asset ID ↔ native ID mapping** is maintained per-app. The Security Graph stores the asset_id as the node key and a `native_refs` property that lists each app's own ID for that asset (e.g. a host node has `native_refs: {MASK: "codyc-wkstn-01", PAKSHIELD: "DEV-WKS-LISA-01"}`).

### 2.3 Event Fabric connectivity

The Event Fabric is the shared bus. Today it's scaffolding in NG's `wolf_pak_security/event_fabric/`. For the three apps to interoperate, the Fabric needs:

1. **An intake endpoint** — a way for apps to push events. The simplest first step: JSON Lines on stdout/file, or an HTTP POST to an intake URL. MASK's bridge already polls the daemon; extend it to forward structured events.
2. **A subscription model** — apps that want to react to events (Policy Engine evaluating detections, AI Orchestrator investigating, Action Gateway executing responses) subscribe to event types they care about.
3. **A storage backend** — the `EventStorage` placeholder needs to become real (SQLite to start, one per tenant or one shared with tenant filters).

**Who pushes what:**

- MASK → Event Fabric: host observations (process list, network connections, user sessions, sysinfo anomalies, LLM reasoning outputs)
- PakShield → Event Fabric: risk events, access events, policy violations, identity anomalies
- Network Guardian → Event Fabric: IDS/IPS alerts, network anomaly detections, firewall verdicts, flow observations

**Who subscribes to what:**

- Security Graph → all event types (builds the graph)
- Policy Engine → detection + risk events (evaluates policy against them)
- AI Orchestrator → detection + risk events (investigates, correlates)
- Action Gateway → policy decisions + orchestration commands (executes responses)

### 2.4 Security Graph node/edge model

The Security Graph connects assets across the three apps. Each app maintains its own node state and feeds it to the graph.

**Node types (one per asset type):**

| Node type | Owns (native state) | Provided by |
|---|---|---|
| Host | hostname, OS, loaded tools, current process list, active connections, user sessions | MASK |
| Device | device_type, OS, hostname, IP, posture_score, compliance_status, encrypted, mfa_capable | PakShield |
| Identity | type, display_name, status, roles, group memberships | PakShield |
| NetworkFlow | src_ip, dst_ip, dst_port, protocol, bytes, flags, verdict | Network Guardian |
| Process | pid, name, user, cmdline, start_time, parent_pid | MASK (tooltip: this is a sub-node of a Host) |
| Policy | policy_type, effect, condition, priority, status | PakShield |
| ThreatIndicator | indicator, indicator_type, confidence, source, expires_at | Threat Intel (feeds) |

**Edge types (relationships between nodes):**

| Edge type | From → To | Meaning |
|---|---|---|
| `host_has_process` | Host → Process | A process is running on this host |
| `host_has_session` | Host → Identity | A user identity has an active session on this host |
| `identity_uses_device` | Identity → Device | An identity is authenticated on this device |
| `flow_involves_host` | NetworkFlow → Host | A network flow touches this host (by IP) |
| `flows_between` | Host → Host | A network flow between two hosts |
| `identity_has_risk` | Identity → RiskIndicator | An identity is associated with a risk indicator |
| `device_has_policy` | Device → Policy | A policy applies to this device |
| `identity_has_role` | Identity → Role | An identity has been granted this role |

**How each app contributes:**

- MASK maintains Host + Process nodes (and their properties) from its tool outputs. Pushes host/process events to the Event Fabric; the Security Graph ingests them and updates the graph.
- PakShield maintains Identity + Device + Policy nodes from its DB. Pushes identity/device/policy events to the Event Fabric.
- Network Guardian maintains NetworkFlow nodes from its packet/flow analysis. Pushes flow events to the Event Fabric.

### 2.5 Threat Intel contract

Threat Intel feeds indicators (IOCs, CVEs, YARA signatures, attack patterns) that all three apps check their observations against.

**Proposed contract:**

- Threat Intel publishes `IntelEvent`s to the Event Fabric with `intel_type` (indicator/campaign/tactic), `indicator`, `indicator_type` (sha256/domain/ip/process_name), `confidence`, `source`, `metadata`.
- Each app subscribes to intel it can use:
  - MASK checks process names and network connections against indicators.
  - Network Guardian checks flow src/dst IPs and payloads against indicators.
  - PakShield checks identity/device risk signals against indicators (e.g. a credential leak indicator matches a credential fingerprint).
- Threat Intel enrichment: when an app emits a detection, the Security Graph enriches it with matching intel before passing it to the Policy Engine / AI Orchestrator.

### 2.6 Policy model alignment

PakShield already has a policy model: `Policy` (policy_type, effect, condition JSON, action, resource_type, priority, enabled, version, status). This is a strong foundation for the Wolf-Pak Policy Engine.

**What needs to align:**

1. **Condition expression language** — PakShield uses JSON conditions (e.g. `{"mfa_verified": False, "risk_score": 0.5}`, `{"hour": {"ge": 22, "or": {"le": 5}}, "resource_type": "database"}`). The Wolf-Pak Policy Engine should adopt the same condition language so policies can be authored once and evaluated by both PakShield (access decisions) and the Policy Engine (response decisions).
2. **Effect vocabulary** — PakShield uses `allow`, `deny`, `audit`, `remediate`. The Policy Engine should use the same vocabulary so a policy authored in PakShield can be evaluated by the Policy Engine for response actions.
3. **Policy ID ↔ asset ID** — Policies apply to resources/devices/identities. The Policy Engine needs to resolve a policy's `resource_type` + `resource_id` to asset IDs in the Security Graph.

### 2.7 Action model alignment

The Action Gateway executes responses. MASK's sandbox + `run_shell` is the proto-action-gateway (runs commands in a constrained environment). PakShield has remediation actions (revoke_access, disable_account, rotate_credential, quarantine_device, enforce_mfa, apply_policy, escalate, accept_risk, close).

**Proposed action descriptor:**

```json
{
  "action_id": "...",
  "action_type": "kill_process",
  "asset_id": "host-codyc-wkstn-01",
  "args": {"pid": 1234},
  "requested_by": "ai-orchestrator",
  "reason": "...",
  "timestamp_ms": 1761900000000
}
```

**Action types (initial set, spanning all three apps):**

| Action type | Executed by | Args | Meaning |
|---|---|---|---|
| `kill_process` | MASK (run_shell → `kill`) | `pid` | Kill a Process by PID |
| `disable_user` | PakShield | `identity_id` | Disable an identity |
| `revoke_access` | PakShield | `identity_id`, `resource_id` | Revoke an identity's access to a resource |
| `rotate_credential` | PakShield | `credential_id` | Rotate a credential |
| `quarantine_device` | PakShield | `device_id` | Quarantine a device |
| `block_flow` | Network Guardian (IPS) | `src_ip`, `dst_ip`, `dst_port` | Block a network flow |
| `isolate_host` | MASK (run_shell → firewall/arp) | `asset_id` | Isolate a host from the network |
| `capture_memory_dump` | MASK (run_shell → tool) | `pid` | Capture a memory dump of a process |
| `run_diagnostic` | MASK (run_shell → tool) | `command` (from allowlist) | Run a diagnostic command (investigation) |

**What each app needs to add:**

- MASK: `run_shell` becomes an action gateway — accepts action descriptors, maps them to pre-approved command templates, executes in sandbox, returns structured result. (MASK's ROADMAP_CORRELATION.md §3.6.)
- PakShield: remediation actions become structured action descriptors that the Action Gateway can invoke (rather than only being triggered internally).
- Network Guardian: IPS block/blocklist actions become structured action descriptors.

---

## 3. Per-project change list

### 3.1 Network Guardian — changes to become the correlation hub

**Priority order:** the Event Fabric intake is the prerequisite; everything else connects to it.

#### P0 — Event Fabric intake (unblocks everything)

1. **Make `EventBus` real** — implement `publish(event_envelope)` that stores the envelope (SQLite to start) and dispatches to subscribers.
2. **Add an intake endpoint** — HTTP POST `/api/event-fabric/intake` that accepts the common event envelope (§2.1), validates the required fields, stores it, and dispatches. Add JSON Lines fallback for apps that can't do HTTP (MASK's bridge can write JSON Lines to a file/socket that the Fabric polls).
3. **Add a subscription API** — `subscribe(event_type, callback)` and `unsubscribe(subscription_id)`. The Policy Engine, AI Orchestrator, and Action Gateway register subscriptions.
4. **Add `EventStorage` implementation** — SQLite table `event_envelopes` with columns for each envelope field, indexed by `asset_id`, `source`, `event_type`, `severity`, `timestamp_ms`.

#### P1 — Security Graph ingestion (unblocks correlation)

5. **Implement `SecurityGraph`** — maintain an in-memory (or SQLite) graph of nodes and edges. Provide `add_node(asset_id, node_type, properties)`, `add_edge(from_asset_id, to_asset_id, edge_type, properties)`, `query(...)`.
6. **Subscribe Security Graph to all event types** — on each event, update the graph: find or create the asset node for `asset_id`, update its properties from `payload`, add edges based on the event type (e.g. a `process_observation` event creates a Process node and a `host_has_process` edge).
7. **Asset ID resolution** — when an event arrives with a `device_id` (PakShield) or `identity_id` (PakShield), resolve it to an asset ID (prefix + native ID) and add the corresponding node if missing.

#### P2 — Threat Intel ingestion (unblocks enrichment)

8. **Implement `IntelIngestor`** — accept IntelEvent envelopes, store them (IntelStore), expire stale indicators.
9. **Implement `IntelEnricher`** — when a DetectionEvent is ingested, check it against stored indicators (by IP, domain, process name, hash) and attach matching intel to the event before dispatching to subscribers.
10. **Add a feed import path** — ability to load indicators from a file/URL (CSV, JSON, STIX 2.1 if feasible) into the IntelStore.

#### P3 — AI Security Orchestrator (unblocks detection/investigation/response)

11. **Implement `DetectionPipeline`** — subscribe to detection + risk events, run them through the existing NG AI engine (Isolation Forest, etc.) for scoring, emit enriched detections.
12. **Implement `InvestigationSession`** — on a high/critical detection, spawn an investigation: query the Security Graph for related nodes (what host, what identity, what flows, what policies), query MASK for host context (process list, connections) if the target is a host, query PakShield for identity context (roles, sessions, risk history) if the target is an identity.
13. **Implement `ResponsePlanner`** — based on the investigation result and policy evaluations, decide on a response action (block_flow, isolate_host, disable_user, etc.) and emit an action request to the Action Gateway.

#### P4 — Policy Engine (unblocks governable response)

14. **Implement `PolicyEngine`** — subscribe to detection + risk events, evaluate them against loaded policies (using the same condition language as PakShield), emit policy decision events (allow/deny/audit/remediate).
15. **Load policies from a shared store** — initially a file/DB that mirrors PakShield's policy table; later, sync from PakShield's API.

#### P5 — Action Gateway (unblocks structured response)

16. **Implement `ActionGateway`** — subscribe to response planner action requests, dispatch to the appropriate app (MASK for host actions, PakShield for identity/device actions, NG IPS for network actions), track action status (pending/in_progress/completed/failed), emit audit events.
17. **Implement action connectors** — `MaskActionConnector` (sends action descriptors to MASK's IPC/`set_config` or a dedicated action endpoint), `PakShieldActionConnector` (calls PakShield's API or DB), `NgapActionConnector` (calls NG's IPS block API).

#### P6 — Dashboard integration (unblocks operator visibility)

18. **Expose the Event Fabric + Security Graph + Policy Engine + Action Gateway state on the dashboard** — new dashboard pages (or extensions to existing pages) showing: live event feed (filtered by app/source), graph visualization (assets and relationships), policy evaluations, action execution status.

---

### 3.2 MASK — changes to become Network/Asset Intelligence and host execution arm

These are drawn from MASK's own `ROADMAP_CORRELATION.md` (§4 and §6), refined against the shared contracts above.

#### P0 — Event schema + asset ID (unblocks Event Fabric ingestion)

1. **Assign MASK an asset ID** — config field `asset_id` (set via `set_config` IPC or `MASK_ASSET_ID` env var). This is the host's stable identity in the Security Graph. **(MASK §6 step 1.)**
2. **Wrap every tool output in the common event envelope** (§2.1) — `{"timestamp_ms":..., "asset_id":..., "source":"MASK", "source_version":"...", "event_type":"...", "severity":"...", "category":"...", "description":"...", "payload":{...}}`. The ring buffer already has the timestamp; the asset ID comes from config; the rest is a serialization layer on each tool's output. `sysinfo` → `event_type: "sysinfo_sample"`, `severity: "info"`, `category: "device"`. `run_shell` output → `event_type: "command_result"`, `severity` based on exit code / content, `category: "process"`. **(MASK §6 step 2.)**

#### P1 — Asset + network intelligence tools (makes MASK a real Network/Asset Intelligence app)

3. **Add a network-telemetry tool: active connections** — run `ss -tunap` (or `netstat -tunap`) in the sandbox, parse into JSON: list of `{local_address, remote_address, state, pid, process_name, user}`. Emit as `event_type: "network_connection_observation"`, `category: "network"`. **(MASK §6 step 3.)**
4. **Add a network-telemetry tool: listening sockets** — run `ss -tlnp` (or `netstat -tlnp`), parse into JSON: list of `{local_address, port, process_name, pid}`. Emit as `event_type: "listening_socket_observation"`, `category: "network"`.
5. **Add an asset-inventory tool: process list** — run `ps aux` (or `ps -eo pid,user,comm,args`) in the sandbox, parse into JSON: list of `{pid, user, comm, args, start_time}`. Emit as `event_type: "process_observation"`, `category: "process"`. **(MASK §6 step 4.)**
6. **Add an asset-inventory tool: user sessions** — run `who` (and `last -n 20` for recent logins) in the sandbox, parse into JSON: list of `{user, terminal, login_time, from_host}`. Emit as `event_type: "user_session_observation"`, `category: "auth"`.
7. **Add an asset-inventory tool: disk mounts** — run `mount` or `df -h` in the sandbox, parse into JSON. Emit as `event_type: "disk_mount_observation"`, `category: "file"`.

#### P2 — Security-aware LLM loop (makes the LLM loop security-aware)

8. **Change the system prompt from health-monitoring to security-reasoning** — the prompt currently says "system-monitoring daemon." It should frame observations as security-relevant and ask the LLM to evaluate them against normal baselines and known indicators. **(MASK §6 step 5.)**
9. **Add threat intel to the prompt** — when the Event Fabric has IntelEvents, feed relevant indicators (process names, IPs, domains) into the LLM prompt so the LLM can evaluate observations against known threats. **(MASK §6 — after step 7.)**
10. **Add an LLM reasoning output event type** — when the LLM decides something is notable, emit an event with `event_type: "llm_reasoning"`, `severity` based on the LLM's own assessment, `payload` carrying the reasoning and any tool calls it decided to make.

#### P3 — Policy + action (makes response safe and governable)

11. **Add a capability policy filter in the tool gateway dispatch path** — start simple: a static allowlist per tool that the LLM can call. This is the seed of the Policy Engine. **(MASK §6 step 6.)**
12. **Convert `run_shell` into an action gateway** — instead of accepting any argv, accept action descriptors (§2.7) mapped to pre-approved command templates. The sandbox's resource limits stay; the command surface shrinks to a known set. **(MASK §3.6, §6.)**
13. **Add an action result event type** — when an action completes, emit `event_type: "action_result"`, `payload` carrying the action_id, action_type, outcome, output.

#### P4 — Event export (connects MASK to the rest of the platform)

14. **Export events to the Event Fabric** — the bridge already polls the daemon; extend it to emit the structured events. First step: JSON Lines to stdout or a file/socket that the Event Fabric polls. Later: HTTP POST to the Event Fabric intake endpoint if MASK gets an HTTP client. **(MASK §6 step 7.)**
15. **Add a MASK outbound API** — an HTTP endpoint (or IPC extension) that NG's InvestigationSession can query for host context: process list, active connections, user sessions, recent events. This is the "host sensor that Network Guardian can query" correlation point. **(MASK §2.1.)**

---

### 3.3 PakShield — changes to become the identity risk pillar and expose identity/device context

These are derived from the correlation points in MASK's `ROADMAP_CORRELATION.md` §2.2 and the shared contracts above.

#### P0 — Asset ID alignment (unblocks Security Graph)

1. **Add an `asset_id` column or computed field to the devices table** — derive it as `device-<tenant_slug>-<device_id>` (or let the Security Graph compute it). This lets PakShield devices be referenced as asset nodes in the graph.
2. **Add an `asset_id` computed field to identities** — derive it as `identity-<tenant_slug>-<identity_id>`. Lets PakShield identities be referenced as asset nodes.

#### P1 — Event export (unblocks Event Fabric ingestion)

3. **Emit risk events to the Event Fabric** — when a `RiskEvent` is created (or when the risk score changes), serialize it to the common envelope (§2.1) with `event_type: "risk_scored"`, `severity` from the RiskEvent, `payload` carrying `risk_score`, `source`, `indicators`, `related_identity_id`, `related_device_id`. Push to the Event Fabric intake.
4. **Emit access events to the Event Fabric** — when an `AccessEvent` is recorded, serialize to the envelope with `event_type: "access_event"`, `payload` carrying `action`, `outcome`, `policy_decisions`, `source_ip`, `session_id`.
5. **Emit finding/violations to the Event Fabric** — when a `Finding` or `Violation` is created, emit `event_type: "finding_created"` / `"violation_created"`, `payload` carrying category, severity, title, description, recommendation.

#### P2 — Identity/device context API (unblocks MASK ↔ PakShield correlation)

6. **Add an API endpoint for host-context queries** — MASK needs to ask PakShield: "given a device_id (host), what identities have sessions on it, what are their risk scores, what policies apply to them?" Endpoints:
   - `GET /api/v1/devices/{device_id}/identities` — identities with active sessions on this device, with risk scores
   - `GET /api/v1/identities/{identity_id}/context` — an identity's roles, groups, devices, recent access events, recent risk events, applicable policies
   - `GET /api/v1/policies/evaluate?device_id=...&identity_id=...` — evaluate policies against a device+identity pair (reuses PakShield's existing policy evaluation)
7. **Add an API endpoint for action execution** — the Action Gateway needs to invoke PakShield remediation actions. Endpoints:
   - `POST /api/v1/actions/execute` — accept an action descriptor (§2.7), execute the corresponding remediation (revoke_access, disable_account, rotate_credential, quarantine_device, enforce_mfa), return result.
8. **Add a policy export endpoint** — the Wolf-Pak Policy Engine needs to load policies from PakShield. Endpoint:
   - `GET /api/v1/policies` — list all active policies with their conditions, effects, priorities.
   - `POST /api/v1/policies` — create/update a policy (so the Policy Engine can push policies back to PakShield if needed).

#### P3 — Tenant-aware event export (unblocks multi-tenant Event Fabric)

9. **Add tenant_id to the event envelope** — PakShield events are per-tenant. The envelope needs a `tenant_id` field (or the `asset_id` encodes it, as in `device-<tenant_slug>-<device_id>`). The Event Fabric stores and filters by tenant.
10. **Add a tenant-scoped intake subscription** — the Event Fabric's subscription model needs to support tenant filters so each tenant's events go to the right place.

---

## 4. Integration contracts (how the three apps talk)

### 4.1 MASK ↔ Network Guardian

| Direction | Mechanism | What flows |
|---|---|---|
| MASK → NG | Event Fabric (MASK pushes host events) | Host observations: sysinfo, process list, network connections, user sessions, LLM reasoning outputs |
| NG → MASK | NG's InvestigationSession queries MASK's outbound API | Host context: process list, active connections, user sessions, recent events (on demand, when NG investigates a host) |
| NG → MASK | Action Gateway → MASK action connector | Response actions: kill_process, isolate_host, capture_memory_dump, run_diagnostic |

### 4.2 PakShield ↔ MASK

| Direction | Mechanism | What flows |
|---|---|---|
| MASK → PakShield | MASK's host-context tools (`who`, `last`, `ps`, `ss`) feed PakShield's risk evaluation | Host identity telemetry: active users, sudo/su activity, processes by user, network connections by user |
| PakShield → MASK | EVENT FABRIC (PakShield pushes identity/risk events) | Identity risk events, access events, policy violations, findings |
| PakShield → MASK | PakShield's host-context API (queried by MASK) | "Who's logged in on host X" — MASK asks PakShield which identities have sessions on a device |
| MASK → PakShield | MASK's host observations (via Event Fabric) | Host context that PakShield uses to enrich identity risk scores (e.g. "admin logged in at 03:00" + MASK's host timeline at 03:00) |

### 4.3 PakShield ↔ Network Guardian

| Direction | Mechanism | What flows |
|---|---|---|
| PakShield → NG | EVENT FABRIC (PakShield pushes risk/access/policy events) | Identity risk scores, access denials, policy violations, credential exposure findings |
| NG → PakShield | NG's network flow events (via Event Fabric) | Network flows involving PakShield device IPs — NG can correlate a device's network behavior with its identity risk |
| Both → Security Graph | Event Fabric → Security Graph ingestion | Combined view: identities (PakShield) + hosts (MASK) + network flows (NG) + policies (PakShield) + threat intel (Threat Intel) |

### 4.4 All three → Event Fabric → Security Graph → AI Orchestrator → Policy Engine → Action Gateway

This is the main data flow:

```
MASK ──► Event Fabric ──► Security Graph ◄── PakShield ──► Event Fabric
                              │
                              ▼
                       AI Orchestrator
                              │
                              ▼
                       Policy Engine
                              │
                              ▼
                       Action Gateway ──► MASK (host actions)
                                      ──► PakShield (identity/device actions)
                                      ──► NG IPS (network actions)
```

---

## 5. Sequencing — what unblocks what

Ordered so earlier items unblock later ones. This is the integration build order, not the app-internal roadmap each team is following.

### Phase 0 — Shared schema + asset IDs (prerequisite)

- [ ] Agree on the common event envelope (§2.1) — all three apps serialize to it at their export boundary.
- [ ] Agree on the asset ID scheme (§2.2) — all three apps use it to identify assets in the Security Graph.
- [ ] MASK assigns its host asset ID (MASK §6 step 1).
- [ ] PakShield adds `asset_id` fields to devices and identities (PakShield §3.3 step 1-2).

**Unlocks:** Event Fabric ingestion from all three apps.

### Phase 1 — Event Fabric intake (unblocks everything else)

- [ ] NG implements `EventBus` + intake endpoint + `EventStorage` (NG §3.1 steps 1-4).
- [ ] MASK wraps tool output in the envelope and exports events (MASK §3.2 steps 2, 14).
- [ ] PakShield emits risk/access/finding events to the Event Fabric (PakShield §3.3 steps 3-5).

**Unlocks:** Security Graph ingestion, AI Orchestrator, Policy Engine, Action Gateway all have events to work with.

### Phase 2 — Security Graph (unblocks correlation visibility)

- [ ] NG implements `SecurityGraph` + subscribes to all event types (NG §3.1 steps 5-7).
- [ ] Each app's events update the graph: MASK host/process nodes, PakShield identity/device/policy nodes, NG flow nodes.

**Unlocks:** Cross-app correlation (an identity risk event + a host process event + a network flow event all about the same asset can be seen together).

### Phase 3 — Threat Intel (unblocks enrichment)

- [ ] NG implements `IntelIngestor` + `IntelStore` + `IntelEnricher` (NG §3.1 steps 8-10).
- [ ] MASK adds threat intel to its LLM prompt (MASK §3.2 step 9).
- [ ] PakShield checks identity/device risk against indicators.

**Unlocks:** Detections enriched with threat context before policy evaluation / orchestration.

### Phase 4 — AI Orchestrator (unblocks detection/investigation/response)

- [ ] NG implements `DetectionPipeline` + `InvestigationSession` + `ResponsePlanner` (NG §3.1 steps 11-13).
- [ ] MASK changes its LLM prompt to security-reasoning (MASK §3.2 step 8).

**Unlocks:** Automated detection scoring, investigation (querying MASK + PakShield for context), response planning.

### Phase 5 — Policy Engine (unblocks governable response)

- [ ] NG implements `PolicyEngine` with the same condition language as PakShield (NG §3.1 step 14-15).
- [ ] PakShield exposes policies via API (PakShield §3.3 step 8).
- [ ] Condition language aligned between PakShield and the Policy Engine (§2.6).

**Unlocks:** Policy-driven allow/deny/audit/remediate decisions on detections.

### Phase 6 — Action Gateway (unblocks structured response)

- [ ] NG implements `ActionGateway` + action connectors (NG §3.1 steps 16-17).
- [ ] MASK converts `run_shell` to an action gateway with action descriptors (MASK §3.2 step 12).
- [ ] PakShield exposes action execution via API (PakShield §3.3 step 7).
- [ ] Action model aligned (§2.7).

**Unlocks:** Structured, auditable response actions across all three apps.

### Phase 7 — Dashboard + operator visibility

- [ ] NG dashboard shows Event Fabric feed, Security Graph, policy evaluations, action status (NG §3.1 step 18).
- [ ] MASK's dashboard becomes the investigation UI (already done — §1.2).

---

## 6. What each team should work on first

### Network Guardian team

Start with **Phase 0 + Phase 1**: make the Event Fabric real (intake endpoint, storage, bus) and wire up the existing `wolf_pak_security/` scaffolding. This is the prerequisite for everything else. The scaffolding already has the class shapes — they need implementations.

### MASK team

Start with **Phase 0**: assign the host asset ID and wrap tool output in the common event envelope. These are small changes (one config field, one serialization layer) that unblock MASK's events flowing into the Event Fabric. Then **Phase 1** (network + asset intelligence tools) to make MASK actually occupy the Network/Asset Intelligence role.

### PakShield team

Start with **Phase 0**: add `asset_id` fields to devices and identities. Then **Phase 1**: emit risk/access/finding events to the Event Fabric. The `core.py` identity engine already has all the data — it just needs to serialize and export it.

---

## 7. Out of scope (for now)

- The PakShield procurement/vendor demo (`app.py` + `VendorPayloadVerification.py`) is a presentation demo and is not part of the identity engine or the correlation. Its Ed25519 verification, crypto engine, risk scoring matrix, and marketplace lifecycle are useful patterns but don't need to be wired into the Wolf-Pak platform for the correlation to work.
- STIX 2.1 / TAXII threat intel feeds — listed as a later enhancement for the Threat Intel layer, not a Phase 0 requirement.
- Multi-tenant Event Fabric isolation — listed as Phase 3 for PakShield; single-tenant works to start.
- Human-in-the-loop gating on the Action Gateway — listed as a later enhancement; structured action descriptors are the prerequisite.
- Bidirectional integration where NG pushes network context to MASK or PakShield — the initial flow is events → Event Fabric → Security Graph; the reverse (NG querying MASK/PakShield for context) comes with the InvestigationSession in Phase 4.
