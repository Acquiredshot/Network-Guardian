# Live Topology and Incident Pages

## Current audited local instance

- Topology: http://127.0.0.1:18000/topology
- NSEP incident register: http://127.0.0.1:18000/incidents
- NSEP aggregate reports and JSON/CSV exports: http://127.0.0.1:18000/reports
- Guardian fleet-generated incident reports: http://127.0.0.1:18080/incidents

The Guardian page requires its own login. It displays fleet-generated Markdown
reports, not every NSEP notification delivered to Event Fabric. To investigate a
NSEP incident, open the NSEP incident register and select **Inspect**. The register
shows detections, risk, timeline, and persisted event/incident relationships.

## What the topology means

The page refreshes every ten seconds and has a manual refresh control. Select a
component with a click or keyboard (Tab, then Enter/Space) to read its role and
the evidence behind its status.

The diagram describes implemented or optional architectural paths:

```text
Sources -> NSEP API -> RabbitMQ -> Celery worker
               |                    |   |
               v                    v   v
           PostgreSQL <---------- results Redis
                                    |
                                    +-> Guardian Event Fabric
                                    +-> Zammad (optional)

Hermes client -> MCP server -> NSEP API (read-only queries)
Mask / PakShield adapters -> Guardian Event Fabric (external configuration)
```

Solid lines are implemented paths. Dashed lines require an external client,
product, or optional configuration. Lines are not real-time packet traffic.

Live evidence is read from existing NSEP endpoints:

- `/api/health`: API HTTP liveness.
- `/api/diagnostics`: PostgreSQL, RabbitMQ and Redis protocol probes.
- `/api/v1/integrations/status`: Guardian, MCP and optional Zammad configuration
  and TCP reachability, not delivery acknowledgement.
- `/api/v1/dashboard/summary` and paged event/incident endpoints: persisted counts
  and latest-event information, not a worker heartbeat.

Unknown is deliberate for worker liveness and external source/client/adapter
activity without a telemetry endpoint. A request failure clears the affected
previous observation and displays an explicit partial-refresh error; it never
preserves a stale green status as if it were current.

## GitHub repository layout

The GitHub repository has Guardian at its root and NSEP inside `NSEP`. The
audited working instance also supports the earlier sibling layout. The HTTP
audit utility detects both layouts without moving private runtime state.

For a fresh clone, create/install the Python environment from the repository root:

```powershell
py -m venv 'NSEP\.venv'
& '.\NSEP\.venv\Scripts\python.exe' -m pip install -e '.[ai,dev]' -e '.\NSEP[test]'
```

Private environment files and `.local-runtime` data are intentionally not pushed.
Before starting NSEP, create/configure `NSEP\.env` for your own database, RabbitMQ
and Redis. The isolated dependency Compose file requires `POSTGRES_USER`,
`POSTGRES_PASSWORD`, `POSTGRES_DB`, `LOCAL_RABBITMQ_USER` and
`LOCAL_RABBITMQ_PASSWORD`; use private unique passwords and corresponding
`DATABASE_URL` and `RABBITMQ_URL`, not committed example credentials.
Its ports are PostgreSQL 15432, RabbitMQ 15673, Redis 16379 on loopback.

For the audited endpoints configure:

```dotenv
REDIS_URL=redis://127.0.0.1:16379/0
NETWORK_GUARDIAN_ENABLED=true
NETWORK_GUARDIAN_DASHBOARD_URL=http://127.0.0.1:18080/
NETWORK_GUARDIAN_INTAKE_URL=http://127.0.0.1:18080/api/event-fabric/intake
ZAMMAD_ENABLED=false
MCP_HOST=127.0.0.1
MCP_PORT=18100
MCP_TRANSPORT=streamable-http
MCP_SERVER_URL=http://127.0.0.1:18100/mcp
NSEP_API_BASE_URL=http://127.0.0.1:18000
```

Apply NSEP's database migrations before first use; Alembic requires
`DATABASE_URL` in its process environment. Existing local credentials, ports,
and migrations are described in [the local audit](LOCAL_PLATFORM_AUDIT.md).

From the cloned repository root, the dashboard-only Guardian launcher is:

```powershell
& '.\NSEP\.venv\Scripts\python.exe' 'scripts\serve_local_dashboard.py'
```

Start the NSEP API, worker and MCP processes from `NSEP` using the separate
terminal commands in [the audit](LOCAL_PLATFORM_AUDIT.md). Substitute your clone
directory for the recorded machine paths. Start only one instance per port.
The launcher does not start the security engine, scanning or enforcement.

After all services are running, rerun the HTTP/handoff audit from `NSEP`:

```powershell
& '.\.venv\Scripts\python.exe' 'tools\audit_local_platforms.py' --output "$env:TEMP\nsep-local-platform-audit.json"
```

This submits one labeled synthetic event and checks the exact persisted handoff.
See the qualified audit verdict before interpreting this as a full protection test.
