# Project Plan

**Status**: Integrated
**Created**: 2026-09-25
**Mode**: NEW
**Execution Mode**: auto

---

## 1. Project Overview

**Goal**: Build a testable network-security event pipeline that accepts events through a FastAPI ingestion service, publishes them durably to RabbitMQ, and processes them with Celery workers for enrichment, deterministic detection, correlation, risk scoring, incident lifecycle management, and narrowly scoped AI investigation summaries.

**App Type**: API only

**API Login**: No

**Mode**: NEW

**Deployment Plan**: No deployment plan found

---

## 2. Backend — Ingestion API

| Component | Technology |
|-----------|-----------|
| **Language** | Python |
| **Runtime** | CPython |
| **Package Manager** | pip |
| **Test Runner** | pytest |
| **Mocking Library** | unittest.mock |
| **Test Command** | pytest |
| **Orchestration** | docker-compose |

The ingestion service validates incoming network security event envelopes, normalizes them into the shared event contract, publishes them durably to RabbitMQ, and exposes liveness and dependency readiness checks. Malformed payloads are rejected before publication using the shared error response contract.

## 3. Backend — Security Workers

| Component | Technology |
|-----------|-----------|
| **Language** | Python |
| **Runtime** | CPython |
| **Package Manager** | pip |
| **Test Runner** | pytest |
| **Mocking Library** | unittest.mock |
| **Test Command** | pytest |
| **Orchestration** | docker-compose |

The Celery worker service consumes RabbitMQ events, parses and enriches records, runs deterministic detection and correlation, calculates risk, persists incidents and event metadata to PostgreSQL, and uses Redis for broker/result support and short-lived coordination. Azure OpenAI is an enhancement for investigation summaries and analyst assistance; detection and risk decisions remain deterministic. Retries route exhausted messages to dead-letter queues.

## 4. Services Required

| Azure Service | Role in App | Environment Variable | Default Value (Local) | Classification |
|---------------|-------------|----------------------|-----------------------|----------------|
| Azure Container Apps | Host the ingestion API and Celery worker processes | `INGESTION_API_URL` | `http://localhost:8000` | Essential |
| PostgreSQL Flexible Server | Store normalized event metadata, detections, risk scores, and incident lifecycle state | `DATABASE_URL` | `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/security_events` | Essential |
| RabbitMQ | Durable event transport, retry queues, and dead-letter routing | `RABBITMQ_URL` | `amqp://guest:guest@localhost:5672//` | Essential |
| Azure Cache for Redis | Celery coordination, result backend, deduplication, and short-lived correlation state | `REDIS_URL` | `redis://localhost:6379/0` | Essential |
| Azure OpenAI | Optional investigation summaries and analyst assistance after deterministic processing | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY` | No local emulator; feature disabled when unset | Enhancement |

RabbitMQ runs as a local Docker Compose dependency and remains RabbitMQ-compatible when hosted as a containerized dependency or approved managed offering.

## 5. Prerequisites

### Run

| Tool | Service(s) | Installed | Version |
|------|------------|-----------|---------|
| Python | * | ✅ | 3.14.3 |
| pip | * | ✅ | 25.3 |

### Debug

| Tool | Service(s) | Installed | Version |
|------|------------|-----------|---------|
| Docker | Ingestion API, Security Workers | ✅ | 29.1.3 |
| Docker Compose | Ingestion API, Security Workers | ✅ | v2.40.3-desktop.1 |
| VS Code Docker extension | Ingestion API, Security Workers | ❓ | Not confirmed |

PostgreSQL, Redis, and RabbitMQ client CLIs were not positively confirmed; they are not required for the planned containerized local workflow. Double-check all `❓` tools before proceeding if direct host-side administration or debugging is needed.

## 6. Project Structure

```
project-root/
├── .azure/
│   └── project-plan.md
├── .env.example
├── .gitignore
├── docker-compose.yml
├── pyproject.toml
├── services/
│   ├── ingestion-api/
│   │   ├── app/
│   │   │   ├── main.py
│   │   │   ├── api/routes.py
│   │   │   ├── config.py
│   │   │   ├── contracts/events.py
│   │   │   ├── messaging/rabbitmq.py
│   │   │   └── services/normalization.py
│   │   └── tests/
│   ├── security-workers/
│   │   ├── app/
│   │   │   ├── celery_app.py
│   │   │   ├── tasks/consume_events.py
│   │   │   ├── detection/rules.py
│   │   │   ├── correlation/engine.py
│   │   │   ├── risk/scoring.py
│   │   │   ├── incidents/lifecycle.py
│   │   │   ├── enrichment/pipeline.py
│   │   │   └── ai/investigation_summary.py
│   │   └── tests/
│   └── shared/
│       ├── contracts/events.py
│       ├── contracts/incidents.py
│       ├── errors.py
│       └── schemas.py
├── migrations/
├── tests/
│   ├── integration/
│   └── fixtures/
└── infra/
    └── README.md
```

## 7. Route Definitions

| # | Method | Path | Description | Request Body | Response Body | Status Codes |
|---|--------|------|-------------|--------------|---------------|--------------|
| 1 | GET | `/api/health` | Liveness check for the ingestion API process | — | `{ status: "ok" }` | 200 |
| 2 | GET | `/api/readiness` | Verify PostgreSQL, RabbitMQ, and Redis connectivity | — | `{ status, services: { database, broker, cache } }` | 200, 503 |
| 3 | POST | `/api/v1/events` | Validate, normalize, and publish one network security event | `{ source, event_type, occurred_at, payload, metadata }` | `{ event_id, accepted_at, status: "queued" }` | 202, 400, 422, 503 |
| 4 | POST | `/api/v1/events/batch` | Validate and publish a bounded batch of network security events | `{ events: [...] }` | `{ accepted, rejected, event_ids }` | 202, 400, 413, 422, 503 |
| 5 | GET | `/api/v1/incidents/{incident_id}` | Retrieve an incident with current risk and lifecycle state | — | `{ incident_id, status, risk, detections, timestamps }` | 200, 404 |

All non-success responses use `{ "error": { "code": "...", "message": "...", "details": null } }` with `VALIDATION_ERROR`, `BAD_REQUEST`, `NOT_FOUND`, `CONFLICT`, and `INTERNAL_ERROR` codes as applicable.

## 8. Next Steps

1. Run **azure-project-scaffold** to execute this plan
2. Run **azure-project-integrate** to wire the services to live dependencies, smoke-test the API, and create the migrations
3. Run **azure-debug-plan** → **azure-debug-generate** for Docker Compose dependencies and VS Code debugging
4. Run the **azure-deploy** agent when ready; it uses **azure-app-onboard** for architecture, cost estimation, IaC generation, provisioning, and health verification