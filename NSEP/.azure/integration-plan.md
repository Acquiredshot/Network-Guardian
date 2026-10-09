# Integration Handoff

## Backend
- Ingestion API: `services/ingestion-api`; run `uvicorn app.main:app --reload --port 8000` with `PYTHONPATH=services/ingestion-api;services`; port `8000`; health `GET /api/health`
- Security workers: `services/security-workers`; run `celery -A app.celery_app.celery worker --loglevel=INFO` with `PYTHONPATH=services/security-workers;services`
- Build/check: `python -m compileall -q services`; tests: `python -m pytest -q`

## Frontend
- None. API-only project.

## API routes
- `GET /api/health`
- `GET /api/readiness`
- `POST /api/v1/events`
- `POST /api/v1/events/batch`
- `GET /api/v1/incidents/{incident_id}`
- OpenAPI: `GET /api/openapi.json`; docs: `GET /api/docs`

## Database
- PostgreSQL; migration tool: Alembic; migration directory: `migrations/`; connection variable: `DATABASE_URL`
- Create schema migrations for normalized events, detections, risk scores, incidents, and lifecycle timestamps.
- **Do not create seed data.**

## Shared contracts
- Python shared package: `services/shared/`; imports use `shared.*` with `PYTHONPATH=services`.

## Dependencies
- Essential: PostgreSQL, RabbitMQ, Redis, ingestion API, security workers.
- Enhancement: Azure OpenAI (`AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, optional deployment setting); deterministic detection and risk decisions must work when unset.
- Local defaults: `DATABASE_URL`, `RABBITMQ_URL`, `REDIS_URL` are documented in `.env.example`; RabbitMQ, Redis, and PostgreSQL are in `docker-compose.yml`.

## Integration Results

- Added Alembic configuration and `migrations/versions/0001_initial_schema.py`; `python -m alembic upgrade head` applied successfully. The migration creates `normalized_events`, `incidents`, `detections`, `risk_scores`, and `incident_lifecycle`, with constraints and indexes and no seed data.
- Connected event publishing to the Celery task protocol, configured worker task discovery, and persisted normalized events, detections, risk scores, incidents, and lifecycle changes to PostgreSQL. Incident reads and readiness checks now use the live dependencies.
- Corrected the Docker Compose build context so both service images can copy repository-root files.
- Built and ran the Compose stack. `GET /api/health` and `/api/readiness` returned 200; single and batch event submissions returned 202; unknown incident lookup returned 404; existing incident lookup returned 200; OpenAPI and docs returned 200.
- End-to-end proof: `POST /api/v1/events` returned 202 for event `1ce05d72-abd0-4c38-a5eb-7c596ca1e15b`; the worker processed it and PostgreSQL-backed `GET /api/v1/incidents/12506fcf-8f7a-4ea6-83ef-02e6cf25ef95` returned 200 with risk 75 and `BRUTE_FORCE` detection. Smoke-test rows were removed after verification.
- Frontend wiring is not applicable: this is an API-only project and has no frontend or mock data layer.
- Verification passed: `python -m compileall -q services`, `python -m pytest -q` (6 passed), and Alembic reported `0001_initial_schema` as current. Compose services were stopped after the end-to-end test.
