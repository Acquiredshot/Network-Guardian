# Local Platform Dependency and Functionality Audit

Audit date: 2026-10-08. Environment: Windows, Python 3.14.3, local Docker Desktop.

## Verdict

**PASS for the tested local dashboards, reciprocal navigation, NSEP processing,
and NSEP-to-Network-Guardian incident delivery.**

**NOT a certification that every product or every action button works.** PakShield
and Mask are not independently installed applications in this workspace. The
return button opens Network Guardian's combined dashboard. Several external-system
pages are intentionally unavailable; installing dependencies cannot supply their
missing APIs. Scans, blocking, quarantine, remote actions, and external AI calls
were deliberately not executed.

Network Guardian is running in dashboard-only mode, not as active protection.
This is a functionality audit, not a production-readiness or security assessment.
Other operating systems were not tested.

## Running components

| Component | Local endpoint | Verified state |
| --- | --- | --- |
| NSEP API and dashboard | http://127.0.0.1:18000/dashboard | Running; health/readiness return 200 |
| Combined Network Guardian dashboard | http://127.0.0.1:18080/ | Running; authenticated pages pass |
| NSEP Celery worker | Local `security-events` queue | Processes synthetic events using Windows solo pool |
| NSEP MCP server | http://127.0.0.1:18100/mcp | Protocol initialization and a tool call pass |
| PostgreSQL 16 Alpine | 127.0.0.1:15432 | Healthy; schema migrations applied |
| RabbitMQ 3.13 management | 127.0.0.1:15673 | Healthy; event queue delivery verified |
| Redis 7 Alpine | 127.0.0.1:16379 | Healthy |

Docker project: `ng-nsep-local`. All exposed dependency ports are loopback-only.
Existing Network Guardian, Zammad, and SEP containers were not stopped,
reconfigured, or used as this audit's database/broker/cache.

Database migrations applied: `0001_initial_schema`, `0002_event_processing_state`.

The four Python application processes are attached to the current assistant
session and may stop when that session closes. Docker containers have a separate
lifetime. Foreground restart commands are provided below.

## Dependencies installed

Both projects use the existing [NSEP virtual environment](../.venv).
Installed editable distributions:

- `security-event-pipeline` with the `test` extra.
- `network-guardian` with the `ai` and `dev` extras.

The missing LangChain/LangGraph framework dependencies were added to Network
Guardian's [optional AI dependency group](../../pyproject.toml).
Installing frameworks does not configure an external model provider.

Selected installed direct dependencies:

| NSEP/API/worker dependency | Installed version |
| --- | --- |
| fastapi | 0.143.0 |
| uvicorn | 0.54.0 |
| celery | 5.6.3 |
| psycopg | 3.3.6, with binary extra |
| redis | 6.4.0 |
| pika | 1.4.4 |
| mcp | 2.3.0 |
| alembic | 1.20.0 |
| pydantic-settings | 2.15.0 |
| httpx | 0.28.1 |
| requests | 2.34.2 |

| Network Guardian / AI / test dependency | Installed version |
| --- | --- |
| pyyaml | 6.0.3 |
| beautifulsoup4 | 4.15.0 |
| lxml | 6.1.3 |
| rich | 15.0.0 |
| psutil | 6.1.1 |
| watchdog | 6.0.0 |
| reportlab | 4.5.1 |
| langchain-core | 1.6.9 |
| langchain-openai | 1.7.0 |
| langgraph | 1.2.14 |
| pytest | 8.4.2 |
| pytest-asyncio | 0.26.0 |

Transitive packages were installed by pip. `pip check`: **no broken requirements**.
These are observed installed versions, not a new cross-platform lock file.
The optional remote-agent extra is not installed or certified by this audit.

## Verification results

| Check | Result | What this proves |
| --- | --- | --- |
| NSEP full test suite | 88 passed | Existing behavior plus navigation, topology and publication regressions |
| Network Guardian full test suite | 723 passed | Existing behavior plus platform-source, navigation and CSP control regressions |
| Total automated tests | 811 passed | No test failures in final isolated runs |
| Live HTTP audit | 112 checks; zero failures | NSEP pages including topology, 12 Guardian pages, discovered local links/assets, selected APIs, incident views |
| Real incident handoff | Passed | Exact newly submitted event found in Guardian's persisted NSEP envelope |
| Publication state matrix on PostgreSQL | 5/5 passed | Late publication does not regress advanced worker states |
| MCP initialization / discovery | Passed | Seven tools are registered and accessible through the actual protocol |
| MCP `search_events` invocation | Passed, no tool error | Read-only tool invocation, not merely a TCP connection |
| Existing linter on new audit/test files and shared database code | Passed | Checked files conform to the configured checks |
| Editor diagnostics on modified core/UI/database files | No errors reported | Editor validation for those files |

An initial Guardian test run failed when a test loaded the real user's persisted
probe-discovery state. The same full suite passed with a fresh, isolated HOME and
USERPROFILE. No user data was deleted and no bridge behavior was changed to hide
the failure. Future suite runs should also isolate the test home.

NSEP emits one pytest-asyncio deprecation warning on Python 3.14; it did not fail
tests. This audit does not assert future Python-version compatibility.

### Browser checks

Live NSEP browser checks passed for:

- Source filtering and reset.
- A filter with no matching source.
- Inspecting and closing the details of a real persisted synthetic event.
- Clicking the switch to Guardian, reaching its expected login page.
- Live topology: six observed healthy/reachable nodes, selectable evidence,
  manual refresh, simulated diagnostic failure clearing stale health, recovery,
  mobile layout at 390 pixels, and incident-report navigation.

## Accessing incidents and live topology

- Live topology: http://127.0.0.1:18000/topology (linked from both dashboards).
- NSEP incidents: http://127.0.0.1:18000/incidents. Choose **Inspect** to see
  detections, risk, timeline, and persisted relationships.
- NSEP statistics and JSON/CSV exports: http://127.0.0.1:18000/reports.
- Guardian fleet-generated Markdown incident reports:
  http://127.0.0.1:18080/incidents (login required). This list can be empty even
  after successful NSEP Event Fabric delivery; those are different data sources.

The topology polls NSEP's existing endpoints every ten seconds. The diagram is
architectural, not a packet capture or discovered network inventory. PostgreSQL,
RabbitMQ and Redis nodes reflect protocol probes; Guardian/MCP/Zammad nodes
reflect configuration and TCP reachability only. Worker, Hermes, Mask/PakShield,
and source activity are not given invented live heartbeat states. Partial
failures show an explicit error and clear previous health observations.

Guardian report/fleet controls were tested using **actual authenticated live HTML
and its unchanged Content-Security-Policy**, served temporarily on a separate
loopback fixture origin with safe synthetic API data. Passed checks:

- High/critical report filtering.
- Report and incident expansion, including a report ID with spaces/slashes.
- Markdown download generation, including exact blob contents.
- Opening a fleet-agent card and closing its detail panel.
- Clicking the rendered Guardian switch back to the live NSEP dashboard.

The temporary fixture server was stopped. These fixture checks validate browser
control wiring, not a real deployed fleet or an external incident-report source.
The integrated browser did not expose a completed file-download event; the
download's generated filename/content were separately verified by instrumentation.

### Actual handoff evidence

Latest audited event: `2bf17975-b8c2-4e92-9a51-9d20d6f3db52`.
Incident: `85beca1b-5d58-429a-9848-1dd1a4bd720c`.
Guardian envelope row: `3`, source `NSEP`.
Final NSEP processing status: `processed`.

The event was explicitly labeled `local-platform-audit`, with six synthetic failed
logins and `audit_only: true`. It triggered the local brute-force detection and
incident pipeline; it did not run a network attack, scan, or enforcement action.
Synthetic audit incidents remain visible and should not be mistaken for real
threats. An earlier, pre-fix synthetic event remains as evidence of the original
failed handoff/status race; it was not silently backfilled.

Read-only MCP tools discovered:
`get_event`, `get_incident`, `search_events`, `get_detection_summary`,
`get_risk_score`, `get_incident_timeline`, `investigate_incident`.

## Bugs fixed during this audit

1. **Guardian rejected NSEP envelopes.** Its producer allowlist did not accept
   `NSEP`, causing HTTP 422 during a real handoff. The contract now accepts NSEP,
   retains the existing producers, and still rejects unknown producers.
2. **Publication overwrote worker completion.** A fast worker could write
   `processed` before the API wrote `published`. Publication now transitions only
   `accepted` to `published`, while recording `published_at` for advanced states.
   The real PostgreSQL matrix preserved `published`, `processing`, `processed`,
   and `failed`; the regression fixtures were removed afterward.
3. **Some Guardian buttons were blocked by CSP.** Report filters, generated report
   and incident expanders/download buttons, fleet cards, and the fleet close
   button used inline HTML handlers. They now use listeners in nonce-authorized
   scripts. CSP was not weakened to permit unsafe inline execution.

Regression tests:
[publication status](../services/ingestion-api/tests/test_publishing_status.py),
[NSEP envelopes](../../tests/test_nsep_envelope.py),
[CSP controls](../../tests/test_csp_dashboard_controls.py).

## Limits and remaining configuration

- The switch links navigate; they do not start applications or share login sessions.
  Guardian still requires its own authentication.
- NSEP sends incidents outward to Guardian. It does not import Guardian's host
  inventory, telemetry, or control APIs. Its related placeholder pages remain
  honestly marked unavailable.
- Zammad integration is disabled in this isolated configuration. Ticketing,
  queues, customers, and analytics require a separately configured Zammad API.
- Hermes is an external MCP client. NSEP's MCP server works, but Hermes itself
  and its investigation/action/activity telemetry are not installed/configured.
- Independent PakShield and Mask applications, live fleet probes, remote-control
  agents, provider credentials, and optional external protection services have
  not been provisioned or verified here.
- No Windows firewall rules, quarantines, IDS/IPS enforcement, malware/network
  scans, remote commands, or paid/external AI requests were triggered for this audit.
- A successful GET or page rendering is not proof that every state-changing control
  is safe and functional. Those operations need a separately authorized test scope.

## Restart the local setup

Run these from PowerShell. Docker Desktop must be running. Keep each application's
foreground command in its own terminal. Do not run the original full-protection
launcher just to view the dashboard.

### Dependencies

```powershell
Set-Location 'C:\Users\elija\Network_Gaurdian2.0\NSEP'
& '.\.venv\Scripts\python.exe' -m pip install -e '.[test]' -e '..\Network-Guardian[ai,dev]'
docker compose --project-name ng-nsep-local --file compose.local-dependencies.yml up -d --wait --wait-timeout 120
```

The existing private [local environment file](../.env) contains the configured
database/broker credentials and alternate ports. Do not publish it or paste its
contents into reports. Initial schema migrations are already applied; when
migrations change, set `DATABASE_URL` privately in the migration process before
running `alembic upgrade head`.

### Terminal 1: NSEP API

```powershell
Set-Location 'C:\Users\elija\Network_Gaurdian2.0\NSEP'
$env:PYTHONPATH='services\ingestion-api;services'
& '.\.venv\Scripts\python.exe' -m uvicorn app.main:app --host 127.0.0.1 --port 18000
```

### Terminal 2: NSEP worker

```powershell
Set-Location 'C:\Users\elija\Network_Gaurdian2.0\NSEP'
$env:PYTHONPATH='services\security-workers;services'
& '.\.venv\Scripts\python.exe' -m celery -A app.celery_app:celery worker --pool=solo --loglevel=INFO
```

### Terminal 3: NSEP MCP

```powershell
Set-Location 'C:\Users\elija\Network_Gaurdian2.0\NSEP'
$env:PYTHONPATH='services\mcp-server;services'
& '.\.venv\Scripts\python.exe' -m app.server
```

### Terminal 4: isolated Guardian dashboard

```powershell
Set-Location 'C:\Users\elija\Network_Gaurdian2.0\Network-Guardian'
& '..\NSEP\.venv\Scripts\python.exe' 'scripts\serve_local_dashboard.py'
```

Username: `admin`. The generated password is stored privately in
`Network-Guardian\.local-runtime\admin_password.txt`; it is not reproduced here.
The launcher isolates local account and event data in that runtime directory and
does not call `engine.start()`.

### Repeat the HTTP/incident audit

This creates one more clearly labeled synthetic incident:

```powershell
Set-Location 'C:\Users\elija\Network_Gaurdian2.0\NSEP'
& '.\.venv\Scripts\python.exe' 'tools\audit_local_platforms.py' --output "$env:TEMP\nsep-local-platform-audit.json"
& '.\.venv\Scripts\python.exe' -m pip check
```

The reusable [audit utility](../tools/audit_local_platforms.py) internally reads the
private local password, checks real routes, and verifies an exact persisted
handoff. Its `passed` flag covers those checks, not every platform capability.
Raw JSON evidence from this audit is also attached to the assistant session.

### Stop only this setup

Stop each foreground Python process with Ctrl+C. To stop only the isolated Docker
stack while preserving its PostgreSQL volume:

```powershell
Set-Location 'C:\Users\elija\Network_Gaurdian2.0\NSEP'
docker compose --project-name ng-nsep-local --file compose.local-dependencies.yml down
```

Do not use volume deletion, global container cleanup, or name-based process kills.
