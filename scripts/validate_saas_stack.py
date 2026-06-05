#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from network_guardian.config import Config
from network_guardian.saas.service import Request, SaaSService
from network_guardian.saas.store import SaaSStore


def _parse_http_response(response: str) -> tuple[int, dict]:
    status_line, rest = response.split("\r\n", 1)
    _, status_code, _ = status_line.split(" ", 2)
    _, body = rest.split("\r\n\r\n", 1)
    parsed = json.loads(body) if body else {}
    return int(status_code), parsed


def _request_json(method: str, path: str, payload: dict | None = None, headers: dict | None = None) -> Request:
    return Request(
        method=method,
        path=path,
        headers=headers or {},
        body=json.dumps(payload or {}).encode("utf-8") if payload is not None else b"",
    )


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _verify_store_backend(config: Config, expected_backend: str) -> None:
    store = SaaSStore(config.saas, config.data_dir)
    _assert(store.backend == expected_backend, f"Expected backend {expected_backend}, got {store.backend}")


def _run_api_smoke(service: SaaSService, slug_suffix: str) -> None:
    unique = f"{slug_suffix}-{int(time.time())}"
    org_slug = f"ng-{unique}".lower().replace("_", "-")
    email = f"owner+{unique}@example.test"

    status, signup = _parse_http_response(
        service._signup(
            _request_json(
                "POST",
                "/api/v1/auth/signup",
                {
                    "organization_name": f"Network Guardian {unique}",
                    "organization_slug": org_slug,
                    "email": email,
                    "password": "Secret123!",
                },
                {"content-type": "application/json"},
            )
        )
    )
    _assert(status == 201 and signup.get("ok"), "Signup failed")
    token = signup["token"]
    org_id = signup["organization"]["id"]

    auth_header = {"authorization": f"Bearer {token}"}

    status, api_key_resp = _parse_http_response(
        service._create_api_key(
            _request_json(
                "POST",
                "/api/v1/org/api-keys",
                {"scope": "fleet:ingest"},
                auth_header,
            )
        )
    )
    _assert(status == 201 and api_key_resp.get("ok"), "API key creation failed")
    api_key = api_key_resp["api_key"]

    status, register = _parse_http_response(
        service._fleet_register(
            _request_json(
                "POST",
                "/api/v1/fleet/register",
                {
                    "agent_id": "agent-smoke-1",
                    "name": "Smoke Agent",
                    "platform": "linux",
                    "metadata": {"version": "1.0.0"},
                },
                {"x-api-key": api_key},
            )
        )
    )
    _assert(status == 201 and register.get("ok"), "Fleet register failed")

    status, report = _parse_http_response(
        service._fleet_report(
            _request_json(
                "POST",
                "/api/v1/fleet/report",
                {
                    "agent_id": "agent-smoke-1",
                    "health": "ok",
                    "findings": [{"severity": "high", "title": "Open port"}],
                },
                {"x-api-key": api_key},
            )
        )
    )
    _assert(status == 202 and report.get("ok"), "Fleet report failed")

    status, checkout = _parse_http_response(
        service._create_checkout_session(
            _request_json(
                "POST",
                "/api/v1/billing/checkout-session",
                {"plan": "growth"},
                auth_header,
            )
        )
    )
    _assert(status == 201 and checkout.get("ok"), "Checkout session creation failed")

    event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_smoke",
                "subscription": "sub_smoke",
                "customer_email": email,
                "current_period_end": int(time.time()) + 3600,
                "metadata": {"organization_id": org_id, "plan": "growth"},
            }
        },
    }
    payload = json.dumps(event).encode("utf-8")

    ts = str(int(time.time()))
    secret = service.config.saas.stripe_webhook_secret.encode("utf-8")
    digest = hmac.new(secret, f"{ts}.{payload.decode('utf-8')}".encode("utf-8"), hashlib.sha256).hexdigest()

    status, webhook = _parse_http_response(
        service._billing_webhook(
            Request(
                method="POST",
                path="/api/v1/billing/webhook",
                headers={"stripe-signature": f"t={ts},v1={digest}"},
                body=payload,
            )
        )
    )
    _assert(status == 200 and webhook.get("ok"), "Webhook processing failed")

    status, org = _parse_http_response(service._get_org(_request_json("GET", "/api/v1/org", None, auth_header)))
    _assert(status == 200 and org.get("ok"), "Org fetch failed")
    _assert(org["organization"]["plan"] == "growth", "Organization plan did not update to growth")
    _assert(org["organization"]["status"] == "active", "Organization status did not update to active")

    status, agents = _parse_http_response(service._fleet_agents(_request_json("GET", "/api/v1/fleet/agents", None, auth_header)))
    _assert(status == 200 and agents.get("ok"), "Agents fetch failed")
    _assert(len(agents.get("agents", [])) >= 1, "Expected at least one registered agent")

    status, reports = _parse_http_response(service._fleet_reports(_request_json("GET", "/api/v1/fleet/reports", None, auth_header)))
    _assert(status == 200 and reports.get("ok"), "Reports fetch failed")
    _assert(len(reports.get("reports", [])) >= 1, "Expected at least one report")

def _configure_common(config: Config, data_dir: Path, database_url: str) -> None:
    config.saas.mode = "saas"
    config.data_dir = data_dir
    config.saas.database_url = database_url
    config.saas.jwt_secret = "validator-secret"
    config.saas.stripe_webhook_secret = "whsec_validator"


def run_sqlite_mode(workdir: Path) -> None:
    config = Config()
    data_dir = workdir / ".ng_validator_sqlite"
    data_dir.mkdir(parents=True, exist_ok=True)
    _configure_common(config, data_dir, f"sqlite:///{data_dir / 'saas.db'}")

    _verify_store_backend(config, "sqlite")
    service = SaaSService(config)
    _run_api_smoke(service, "sqlite")


def run_postgres_mode(workdir: Path, database_url: str) -> None:
    config = Config()
    data_dir = workdir / ".ng_validator_postgres"
    data_dir.mkdir(parents=True, exist_ok=True)
    _configure_common(config, data_dir, database_url)

    _verify_store_backend(config, "postgres")
    service = SaaSService(config)
    _run_api_smoke(service, "postgres")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="validate_saas_stack",
        description="One-command SaaS stack validator (auth, fleet, billing, and tenancy paths).",
    )
    parser.add_argument(
        "--mode",
        choices=["sqlite", "postgres", "all"],
        default="all",
        help="Validation mode: sqlite, postgres, or all (default).",
    )
    parser.add_argument(
        "--postgres-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL DATABASE_URL for postgres/all mode.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]

    try:
        if args.mode in ("sqlite", "all"):
            run_sqlite_mode(root)
            print("[OK] SQLite SaaS validation passed")

        if args.mode in ("postgres", "all"):
            if not args.postgres_url:
                raise RuntimeError("--postgres-url (or DATABASE_URL) is required for postgres/all mode")
            run_postgres_mode(root, args.postgres_url)
            print("[OK] PostgreSQL SaaS validation passed")

        print("[OK] SaaS stack validation complete")
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
