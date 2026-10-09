# Network Security Event Pipeline Implementation Audit

Audit date: 2026-09-26  
Scope: current workspace source, tests, migrations, and the current SOC dashboard. The supplied architecture diagram and sample event are treated as intended capabilities, not evidence of implementation.

## Executive Summary

The repository contains a working, narrow event-ingestion pipeline: FastAPI validates an event envelope, assigns an event ID, persists and queues it, then a Celery worker enriches it, applies two rules, scores detections, and creates an incident when a rule fires. The SOC dashboard now reads counts and time buckets from persisted events, browses/searches events, detections, and incidents with bounded pagination, and displays incident timelines and only database-backed event/incident/detection relationships.

The repository does **not** implement the full conceptual architecture shown in the diagram. In particular, it has no entity model/graph, multi-event correlation in the worker path, MITRE mapping, evidence store, notification delivery, or response automation. The new graph is intentionally limited to persisted event, incident, and detection foreign-key relationships.

The supplied event example is not the current API contract. The API requires `occurred_at` and an object-valued `payload`; the server generates `event_id` and `accepted_at`. `timestamp`, `severity`, `user`, `source_ip`, `destination_ip`, `action`, and incoming `status` are not top-level `EventEnvelope` fields. Because Pydantic's default extra-field behavior is to ignore unknown fields, these fields are not persisted as event columns; without the required `occurred_at` and `payload`, the example is rejected.

## Current Architecture and Flow

The app uses FastAPI with plain static HTML, CSS, and JavaScript. There is no React, Vue, or frontend build system. `services/ingestion-api/app/main.py` creates the FastAPI app, includes the API router, mounts `/static`, serves the SOC dashboard at `/`, exposes Swagger at `/docs`, and retains the custom API reference at `/api/docs`. OpenAPI JSON remains at `/api/openapi.json`.

Current single-event flow:

1. `POST /api/v1/events` validates an `EventEnvelope`.
2. `app/services/normalization.py` assigns a UUID `event_id` and UTC `accepted_at`.
3. `shared/database.py` inserts the event in `normalized_events` and ignores a duplicate primary key.
4. `app/messaging/rabbitmq.py` enqueues the normalized event with Celery on the `security-events` queue.
5. The API updates the event status to `published` and returns `QueuedResponse`.
6. `security-workers/app/tasks/consume_events.py` updates status, enriches the event, applies detection rules, scores detections, and persists the processed event.
7. If detections exist, the worker creates and persists an incident, detections, risk score, and an initial lifecycle row.
8. `GET /api/v1/events/{event_id}` returns processing status only. `GET /api/v1/incidents/{incident_id}` returns incident status, risk, detections, and timestamps.

The batch endpoint loops through the supplied events and uses the same persistence/queueing path. It accepts 1-100 events per request; it is not a streaming ingestion endpoint.

## Existing HTTP API

| Method and path | What it exposes | Dashboard use |
|---|---|---|
| `GET /api/health` | API liveness only; does not probe dependencies | API health indicator |
| `GET /api/readiness` | Database, broker, and cache readiness; returns 503 when degraded | Overall pipeline readiness |
| `GET /api/diagnostics` | API status/version and dependency status/latency | API, database, broker, cache telemetry |
| `GET /api/v1/dashboard/summary` | Event/active detection/active incident counts and 24 hourly event buckets | Dashboard KPIs, heat map, activity chart, threat rule summary |
| `GET /api/v1/events` | Searchable, filterable, sortable, paginated event records | Event explorer and event detail |
| `GET /api/v1/detections` | Searchable, filterable, paginated detections with linked event/incident | Threat explorer |
| `GET /api/v1/incidents` | Searchable, filterable, paginated incident summaries | Incident register |
| `GET /api/v1/incidents/{incident_id}/timeline` | Persisted accepted/published/processed, detection, and lifecycle entries | Incident timeline |
| `GET /api/v1/incidents/{incident_id}/graph` | Event–incident and event–detection relationships derived from existing foreign keys | Selected-incident relationship explorer |
| `POST /api/v1/events` | Accepts, normalizes, persists, and queues one event | Event submission form |
| `POST /api/v1/events/batch` | Accepts a bounded batch and returns accepted event IDs | API docs only; no batch UI currently |
| `GET /api/v1/events/{event_id}` | Processing status/timestamps/retries/failure reason | Event ID lookup and partial drill-down |
| `GET /api/v1/incidents/{incident_id}` | Incident status/risk/detections/timestamps | Incident ID lookup and partial drill-down |
| `GET /api/openapi.json` | OpenAPI document | Swagger spec source |
| `GET /docs` | FastAPI Swagger UI | Interactive API documentation |
| `GET /api/docs` | Existing custom API reference page | Preserved compatibility |
| `GET /` | SOC dashboard | Primary application page |

The `/` and `/docs` routes are part of the current workspace after the dashboard changes; they were not present in the earlier application entry point. Existing `/api/*` endpoint names and response schemas are unchanged.

## Existing Schemas

| Schema | Actual fields and constraints | Important limitation |
|---|---|---|
| `EventEnvelope` | `source` (1-128 chars), `event_type` (1-128 chars), `occurred_at` (`datetime`), `payload` (object), `metadata` (object, defaults to `{}`) | No first-class severity, user, source/destination IP, action, or status fields |
| `NormalizedEvent` | `EventEnvelope` plus generated `event_id` (UUID) and `accepted_at` (datetime) | ID and accepted time are assigned by the API, not supplied by the caller |
| `BatchRequest` | `events`, list size 1-100 | No per-item partial validation result contract |
| `BatchResponse` | `accepted`, `rejected`, `event_ids` | Normal success path accepts each validated event; errors fail the request |
| `QueuedResponse` | `event_id`, `accepted_at`, `status` (defaults to `queued`) | Reports acceptance/queueing, not completed processing |
| `EventStatusResponse` | `event_id`, `status`, accepted/published/processed times, retry count, failure reason | Does not return source, event type, payload, or event classification |
| `IncidentResponse` | `incident_id`, `status`, `risk`, `detections`, `timestamps` | No title, priority, analyst, notes, evidence, affected assets, or related event list |
| `HealthResponse` | `status`, optional `services` map | Liveness/readiness contract; no event counters |
| `DiagnosticsResponse` | `status`, `service`, `version`, dependency diagnostics | Dependency status and latency only; no worker/queue health |
| `PageResponse[T]`, `EventRecord`, `DetectionRecord`, `IncidentRecord` | Typed paged dashboard records over current tables | Does not add or duplicate persistence schemas |
| `DashboardSummary`, `ActivityBucket`, `RuleCount` | Aggregated counts, 24 hourly buckets, active detections grouped by current rule/severity | No synthetic metrics; zero buckets reflect database queries |
| `TimelineEntry`, `IncidentGraph`, `GraphNode`, `GraphEdge` | Timeline and FK-backed relationship response types | Graph contains only event, incident, and detection nodes |

The actual schema definitions are in `services/shared/contracts/events.py`, `services/shared/contracts/incidents.py`, and `services/shared/schemas.py`.

## Capability Audit

Status meanings: **IMPLEMENTED** means the capability is present and connected in the application path; **PARTIALLY IMPLEMENTED** means only a limited component or unconnected helper exists; **NOT IMPLEMENTED** means no corresponding working backend capability was found. Dashboard-only visualization is explicitly called out and is not treated as backend functionality.

| # | Capability | Status | Existing files / APIs | What works | Missing / recommended next step |
|---:|---|---|---|---|---|
| 1 | Event ingestion | IMPLEMENTED | `ingestion-api/app/api/routes.py`; `POST /api/v1/events` | Validates, normalizes, persists, queues, and returns an event ID | Add list/search APIs only if the explorer needs them |
| 2 | Batch ingestion | IMPLEMENTED | `shared/contracts/events.py`; `routes.py`; `POST /api/v1/events/batch` | Accepts 1-100 envelopes through the queue path | No streaming transport or per-item error report |
| 3 | Event validation | PARTIALLY IMPLEMENTED | `shared/contracts/events.py`; `tests/test_routes.py` | Pydantic validates required fields, strings/lengths, datetime parsing, and object payload/metadata; invalid requests return 422 | No dedicated timestamp policy, source catalog, severity validation, or validation pipeline with accept/reject reasons |
| 4 | Event normalization | IMPLEMENTED | `ingestion-api/app/services/normalization.py` | Generates UUID and accepted timestamp; worker lowercases a derived `normalized_source` | Additional canonical field normalization is not present |
| 5 | Deduplication | PARTIALLY IMPLEMENTED | `shared/database.py`; migration `0001_initial_schema.py` | Persistence is idempotent for a repeated `event_id` primary key | The API generates a new ID per request and `EventEnvelope` has no idempotency key/content fingerprint; duplicate source events are not detected |
| 6 | Queueing | IMPLEMENTED | `ingestion-api/app/messaging/rabbitmq.py`; `security-workers/app/celery_app.py` | Celery publishes to RabbitMQ queue `security-events`; Redis is configured as Celery result backend | No queue-depth or consumer-lag API |
| 7 | Processing | IMPLEMENTED | `security-workers/app/tasks/consume_events.py` | Celery task processes events, records status, retries exceptions with backoff up to three retries | No separate processing metrics/worker readiness endpoint |
| 8 | Enrichment | PARTIALLY IMPLEMENTED | `security-workers/app/enrichment/pipeline.py` | Adds lowercase `normalized_source` | No threat-intel, asset, identity, geo, or external enrichment |
| 9 | Correlation | PARTIALLY IMPLEMENTED | `security-workers/app/correlation/engine.py`; `consume_events.py` | `correlate()` can return source/rule summary for one event's detections | Helper is not called by the processing task and does not correlate multiple events or entities; wire real correlation only with defined grouping rules |
| 10 | Classification | PARTIALLY IMPLEMENTED | `security-workers/app/detection/rules.py` | Two narrow conditions classify detections by failed-login count or malware/ransomware event type | No general event taxonomy or classification service |
| 11 | Risk scoring | IMPLEMENTED | `security-workers/app/risk/scoring.py`; `shared/database.py` | Deterministic max-severity score, capped 0-100, persisted for incidents | No confidence factor or multi-signal aggregation |
| 12 | Detection rules | IMPLEMENTED | `security-workers/app/detection/rules.py`; `security-workers/tests/test_pipeline.py` | `BRUTE_FORCE` at `failed_logins >= 5`; `MALWARE_ACTIVITY` for `malware`/`ransomware` event types | No signatures/anomaly model/rule management API; no detection list API |
| 13 | Threat objects | PARTIALLY IMPLEMENTED | `detections` table; `GET /api/v1/detections`; `shared/contracts/dashboard.py` | Actual rule/severity detections are searchable and link to their event and incident | No separate threat-intel object, confidence, entity links, or ATT&CK mapping |
| 14 | Entity relationships | PARTIALLY IMPLEMENTED | `GET /api/v1/incidents/{incident_id}/graph`; `shared/database.py` | Graph returns persisted event–incident and event–detection links | No user/device/IP/domain/process entity records or inferred relationships |
| 15 | Alerts | PARTIALLY IMPLEMENTED | Detection rules and incident creation in `consume_events.py` | A detection causes an incident to be created | No standalone alert model, alert state, or alert API |
| 16 | Incidents | PARTIALLY IMPLEMENTED | `shared/contracts/incidents.py`; `shared/database.py`; `GET /api/v1/incidents` and `GET /api/v1/incidents/{incident_id}` | Incidents are listed/searched/paged and include actual event source/type, risk, status, detections, and timestamps | No assignment, notes, title, priority, or incident status mutation workflow; one event per incident in the current schema |
| 17 | Incident timelines | PARTIALLY IMPLEMENTED | `incident_lifecycle` table; `GET /api/v1/incidents/{incident_id}/timeline` | API combines persisted event processing timestamps, detections, and lifecycle rows | Only initial lifecycle rows are currently written; status transitions remain unimplemented |
| 18 | Evidence | NOT IMPLEMENTED | No evidence schema or routes found | Detection rule/severity details are retained | No evidence artifact/reference model or evidence endpoint |
| 19 | MITRE ATT&CK mappings | NOT IMPLEMENTED | No tactic/technique fields or mapping files found | None | Add curated mappings with provenance; do not infer ATT&CK techniques from arbitrary event types |
| 20 | Playbooks | NOT IMPLEMENTED | No playbook backend found | Dashboard has a clearly labeled static response preview only | Define playbook model and approval/execution contract before connecting automation |
| 21 | Notifications | NOT IMPLEMENTED | No notification provider/task/routes found | None | Add delivery provider, delivery state, and retry/audit records if required |
| 22 | Response simulation | PARTIALLY IMPLEMENTED | Dashboard playbook preview only | Shows trigger/action/notify as a non-executing visualization | No backend simulation result, approval record, or audit trail; keep all actions non-destructive until implemented |
| 23 | Metrics | PARTIALLY IMPLEMENTED | `GET /api/diagnostics`; `GET /api/v1/dashboard/summary`; `shared/database.py` | Persisted event/active incident/active detection counts, hourly event buckets, and dependency latency | No queue/worker health, throughput rate, or detection confidence metrics |
| 24 | Audit logging | PARTIALLY IMPLEMENTED | `services/shared/logging.py`; API middleware; worker task logs | Structured JSON request/processing logs, request IDs, and sensitive-name redaction | No durable audit event store, actor/action records, or retention/query API |
| 25 | Authentication | NOT IMPLEMENTED | No auth dependency/middleware/config found | None | Add authentication before exposing operational data outside a trusted local environment |
| 26 | RBAC | NOT IMPLEMENTED | No roles, permissions, or policy checks found | None | Define analyst/admin/response permissions after authentication is selected |
| 27 | Event search | IMPLEMENTED | `GET /api/v1/events`; `shared/database.py` | Case-insensitive query searches UUID, source, event type, payload, and metadata | Protect payload/search access with authentication before untrusted deployment |
| 28 | Event filtering | IMPLEMENTED | `GET /api/v1/events` | Filters source, event type, processing status, and detection severity; stable allowlisted sorting | No direct user/IP/action filters because those are not first-class schema fields |
| 29 | Pagination | IMPLEMENTED | Event, detection, and incident list APIs | Bounded `limit` (1-100) and offset pagination with total count | Cursor pagination can be considered for very large datasets |
| 30 | Dashboard data APIs | IMPLEMENTED | Summary, event/detection/incident lists, incident timeline/graph, health/readiness/diagnostics | Dashboard consumes real persisted counts, series, detection and incident records, and persisted relationships | No entity graph, worker health, ATT&CK, or response execution API |

## Current Dashboard Connectivity

| Dashboard component | Current source | Data-driven status |
|---|---|---|
| Pipeline health KPI / top-right status | `/api/health`, `/api/readiness`, `/api/diagnostics` | Live; displays operational/degraded/offline/unknown based on responses |
| API, database, broker, cache telemetry | `/api/health`, `/api/diagnostics` | Live; status and latency are read from backend responses |
| Event ingestion, detection, incident-processing probes | No dedicated probe in current API | N/A; shown as unreported |
| Network events, active threats, incident counts | `GET /api/v1/dashboard/summary` | Live counts from `normalized_events`, active incidents, and detections attached to active incidents |
| Heat map and network activity | `GET /api/v1/dashboard/summary` | Live 24-hour event buckets grouped by `occurred_at`; empty buckets are returned as zero |
| Threat summary | Summary endpoint plus `GET /api/v1/detections` | Live detection counts by persisted rule/severity and searchable detection rows |
| Triage rule reference | `security-workers/app/detection/rules.py` | Shows the two implemented rule conditions and severity; counts and MITRE mapping are not claimed |
| Event/incident graph | `GET /api/v1/incidents/{incident_id}/graph` | Actual event, incident, and detection relationships; no inferred entity nodes |
| Event submit and event lookup | `POST /api/v1/events`, `GET /api/v1/events/{event_id}` | Connected; event lookup returns processing metadata, not the original event payload |
| Event explorer | `GET /api/v1/events` | Search, source/type/status/severity filters, allowlisted sorting, pagination, and payload detail for selected events |
| Threat explorer | `GET /api/v1/detections` | Actual detections with source, event type, incident, risk, and severity |
| Incident register/drill-down | Incident list/detail, timeline, and graph routes | Connected to current persisted incident fields and lifecycle/detection rows |
| Playbook/response panel | Frontend only | Clearly labeled simulation/preview; no response action is executed |
| IDS, IPS, and reports navigation | No corresponding API capabilities | Explicit coverage/no-aggregation states |

## Components Not to Rebuild

- Keep `EventEnvelope`, `NormalizedEvent`, `BatchRequest`, `BatchResponse`, `QueuedResponse`, and `EventStatusResponse` as the event contract source of truth.
- Keep `IncidentResponse`, the incidents/detections/risk-score persistence, and the existing incident lookup route.
- Keep the ingestion router and health/readiness/diagnostics probes.
- Keep the existing Celery/RabbitMQ processing path, worker retry policy, detection rules, and risk scorer.
- Keep `/api/openapi.json`, the built-in `/docs` Swagger UI, and the legacy custom `/api/docs` reference.
- Do not replace the existing validation with a parallel frontend/backend model. The dashboard event form submits the current `EventEnvelope` contract.

## Backend APIs Needed for a Fully Data-Driven SOC Dashboard

Prioritize these only after approving the audit and UI needs:

1. Worker/queue diagnostics if the dashboard must show processing, detection, correlation, and incident-engine health separately from database/broker connectivity.
2. Entity schemas and provenance-backed relationship APIs before adding user/device/IP/domain/process nodes to the graph.
3. Explicit, curated MITRE tactic/technique/sub-technique fields before claiming ATT&CK coverage.
4. Auth/RBAC and durable audit-record design before exposing event payloads or enabling multi-user incident management.
5. A playbook simulation/approval contract before any response execution. The current UI preview remains non-executing.

## Verification Evidence and Assumptions

- `python tools/verify.py --skip-live`: passed compilation, dependency imports, 19 tests, Compose config validation, and secret-safety checks.
- Live preview on port 8001: `/`, `/docs`, `/api/docs`, the summary/list APIs, `/api/health`, `/api/readiness`, and `/api/diagnostics` returned expected responses; database, broker, and cache reported ready.
- Live data currently includes 2 events, 2 active incidents, and 2 active detections; these values are read from the local database, not seeded by the dashboard.
- Those stored events' occurrence timestamps are outside the current 24-hour activity window, so the recent heat map correctly shows an empty-window state while the all-time event KPI remains 2.
- Browser checks rendered actual event and incident rows, the time-bucket chart/empty state, event detail, incident timeline, and FK-backed graph nodes/edges.
- Read-only UI lookups with unknown UUIDs returned the expected not-found messages; no test event was inserted.
- Port 8000 is occupied by an existing local listener serving an older app process. The updated container preview is therefore exposed at `http://127.0.0.1:8001/`; the existing port-8000 process was left untouched.
- No event/incident list, count, time-series, entity-graph, worker-health, authentication, or RBAC behavior is assumed beyond the inspected source.

## Recommended Next Step

The dashboard data surfaces are now connected to existing persisted records. Remaining work is auth/RBAC, worker/queue diagnostics, entity modeling, curated ATT&CK mapping, and approved incident/response workflows; do not imply those capabilities exist until implemented.