import json
from datetime import datetime, timezone

from network_guardian.config import Config
from network_guardian.saas.service import Request, SaaSService
from network_guardian.saas.store import SaaSStore


def _parse_http_body(response: str) -> dict:
    _, body = response.split("\r\n\r\n", 1)
    return json.loads(body)


def _auth_header(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def _stripe_signature(payload: bytes, secret: str, timestamp: int = 1_700_000_000) -> str:
    import hashlib
    import hmac
    import time

    if timestamp == 1_700_000_000:
        timestamp = int(time.time())

    signed_payload = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def test_signup_login_and_org_view(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path
    cfg.saas.mode = "saas"
    cfg.saas.database_url = f"sqlite:///{tmp_path / 'saas.db'}"
    cfg.saas.jwt_secret = "test-secret"
    service = SaaSService(cfg)

    signup = service._signup(
        Request(
            method="POST",
            path="/api/v1/auth/signup",
            headers={"content-type": "application/json"},
            body=json.dumps(
                {
                    "organization_name": "Acme Security",
                    "organization_slug": "acme",
                    "email": "owner@acme.test",
                    "password": "Secret123!",
                }
            ).encode("utf-8"),
        )
    )
    signup_body = _parse_http_body(signup)
    assert signup_body["ok"] is True
    assert signup_body["organization"]["slug"] == "acme"

    login = service._login(
        Request(
            method="POST",
            path="/api/v1/auth/login",
            headers={"content-type": "application/json"},
            body=json.dumps(
                {
                    "organization_slug": "acme",
                    "email": "owner@acme.test",
                    "password": "Secret123!",
                }
            ).encode("utf-8"),
        )
    )
    login_body = _parse_http_body(login)
    assert login_body["ok"] is True

    org_view = service._get_org(
        Request(
            method="GET",
            path="/api/v1/org",
            headers=_auth_header(login_body["token"]),
            body=b"",
        )
    )
    org_body = _parse_http_body(org_view)
    assert org_body["organization"]["slug"] == "acme"


def test_api_key_register_report_and_list_agents(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path
    cfg.saas.mode = "saas"
    cfg.saas.database_url = f"sqlite:///{tmp_path / 'saas.db'}"
    cfg.saas.jwt_secret = "test-secret"
    service = SaaSService(cfg)

    signup_body = _parse_http_body(
        service._signup(
            Request(
                method="POST",
                path="/api/v1/auth/signup",
                headers={"content-type": "application/json"},
                body=json.dumps(
                    {
                        "organization_name": "Acme Security",
                        "organization_slug": "acme",
                        "email": "owner@acme.test",
                        "password": "Secret123!",
                    }
                ).encode("utf-8"),
            )
        )
    )
    token = signup_body["token"]

    api_key_body = _parse_http_body(
        service._create_api_key(
            Request(
                method="POST",
                path="/api/v1/org/api-keys",
                headers=_auth_header(token),
                body=json.dumps({"scope": "fleet:ingest"}).encode("utf-8"),
            )
        )
    )
    assert api_key_body["ok"] is True
    api_key = api_key_body["api_key"]

    register_body = _parse_http_body(
        service._fleet_register(
            Request(
                method="POST",
                path="/api/v1/fleet/register",
                headers={"x-api-key": api_key},
                body=json.dumps(
                    {
                        "agent_id": "agent-1",
                        "name": "Phoenix",
                        "platform": "macOS",
                        "metadata": {"version": "1.0.0"},
                    }
                ).encode("utf-8"),
            )
        )
    )
    assert register_body["ok"] is True
    assert register_body["agent"]["id"] == "agent-1"

    report_body = _parse_http_body(
        service._fleet_report(
            Request(
                method="POST",
                path="/api/v1/fleet/report",
                headers={"x-api-key": api_key},
                body=json.dumps(
                    {
                        "agent_id": "agent-1",
                        "platform": "macOS",
                        "health": "ok",
                        "findings": [{"severity": "high", "title": "Open port"}],
                    }
                ).encode("utf-8"),
            )
        )
    )
    assert report_body["ok"] is True
    assert report_body["report"]["agent_id"] == "agent-1"

    agents_body = _parse_http_body(
        service._fleet_agents(
            Request(
                method="GET",
                path="/api/v1/fleet/agents",
                headers=_auth_header(token),
                body=b"",
            )
        )
    )
    assert agents_body["ok"] is True
    assert len(agents_body["agents"]) == 1
    assert agents_body["agents"][0]["organization_id"] == signup_body["organization"]["id"]

    reports_body = _parse_http_body(
        service._fleet_reports(
            Request(
                method="GET",
                path="/api/v1/fleet/reports",
                headers=_auth_header(token),
                body=b"",
            )
        )
    )
    assert reports_body["ok"] is True
    assert len(reports_body["reports"]) == 1
    assert reports_body["reports"][0]["report"]["health"] == "ok"


def test_hosted_app_page_and_billing_flow(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path
    cfg.saas.mode = "saas"
    cfg.saas.database_url = f"sqlite:///{tmp_path / 'saas.db'}"
    cfg.saas.jwt_secret = "test-secret"
    cfg.saas.stripe_webhook_secret = "whsec_test"
    service = SaaSService(cfg)

    app_page = service._page_app()
    assert "Network Guardian Cloud" in app_page
    assert "/api/v1/billing/checkout-session" in app_page

    signup_body = _parse_http_body(
        service._signup(
            Request(
                method="POST",
                path="/api/v1/auth/signup",
                headers={"content-type": "application/json"},
                body=json.dumps(
                    {
                        "organization_name": "Acme Security",
                        "organization_slug": "acme",
                        "email": "owner@acme.test",
                        "password": "Secret123!",
                    }
                ).encode("utf-8"),
            )
        )
    )
    token = signup_body["token"]

    checkout_body = _parse_http_body(
        service._create_checkout_session(
            Request(
                method="POST",
                path="/api/v1/billing/checkout-session",
                headers=_auth_header(token),
                body=json.dumps({"plan": "growth"}).encode("utf-8"),
            )
        )
    )
    assert checkout_body["ok"] is True
    assert checkout_body["provider"] == "mock"
    assert checkout_body["plan"] == "growth"

    event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_123",
                "subscription": "sub_123",
                "customer_email": "owner@acme.test",
                "current_period_end": int(datetime.now(timezone.utc).timestamp()) + 3600,
                "metadata": {
                    "organization_id": signup_body["organization"]["id"],
                    "plan": "growth",
                },
            }
        },
    }
    payload = json.dumps(event).encode("utf-8")
    webhook_body = _parse_http_body(
        service._billing_webhook(
            Request(
                method="POST",
                path="/api/v1/billing/webhook",
                headers={"stripe-signature": _stripe_signature(payload, cfg.saas.stripe_webhook_secret)},
                body=payload,
            )
        )
    )
    assert webhook_body["ok"] is True

    org_body = _parse_http_body(
        service._get_org(
            Request(
                method="GET",
                path="/api/v1/org",
                headers=_auth_header(token),
                body=b"",
            )
        )
    )
    assert org_body["organization"]["plan"] == "growth"
    assert org_body["organization"]["status"] == "active"

    portal_body = _parse_http_body(
        service._create_portal_session(
            Request(
                method="POST",
                path="/api/v1/billing/portal-session",
                headers=_auth_header(token),
                body=b"{}",
            )
        )
    )
    assert portal_body["ok"] is True
    assert portal_body["portal_url"].endswith("/app")


def test_postgres_store_backend_selection(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path
    cfg.saas.database_url = "postgresql://user:pass@localhost/network_guardian"
    store = SaaSStore(cfg.saas, cfg.data_dir)
    assert store.backend == "postgres"
