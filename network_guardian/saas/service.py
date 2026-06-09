from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import signal
from dataclasses import dataclass
from typing import Any

from network_guardian.config import Config
from network_guardian.saas.auth import TokenError, create_access_token, verify_access_token
from network_guardian.saas.billing import BillingError, StripeBilling
from network_guardian.saas.store import SaaSStore
from network_guardian.saas.tenancy import TenantContext, TenancyError, require_org_access, require_role
from network_guardian.saas.ui import get_saas_app_page

logger = logging.getLogger("network_guardian.saas")

_CONTENT_JSON = "application/json"
_CONTENT_TEXT = "text/plain"


@dataclass(slots=True)
class Request:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class SaaSService:
    MAX_HEADER_BYTES = 8192
    REQUEST_TIMEOUT = 10.0

    def __init__(self, config: Config, host: str = "127.0.0.1", port: int = 8081) -> None:
        self.config = config
        self.host = host
        self.port = port
        self.store = SaaSStore(config.saas, config.data_dir)
        self.billing = StripeBilling(config.saas)
        self.store.migrate()
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logger.info("SaaS service listening on %s:%s", self.host, self.port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def run_forever(self) -> None:
        await self.start()
        stop_event = asyncio.Event()

        def _sig(*_: object) -> None:
            stop_event.set()

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _sig)
            except NotImplementedError:
                signal.signal(sig, lambda *_: stop_event.set())
        await stop_event.wait()
        await self.stop()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await self._read_request(reader)
            response = await self.handle_request(request)
            writer.write(response.encode("utf-8"))
            await writer.drain()
        except TenancyError as exc:
            writer.write(self._json_response(403, {"ok": False, "message": str(exc)}).encode("utf-8"))
            await writer.drain()
        except TokenError as exc:
            writer.write(self._json_response(401, {"ok": False, "message": str(exc)}).encode("utf-8"))
            await writer.drain()
        except BillingError as exc:
            writer.write(self._json_response(400, {"ok": False, "message": str(exc)}).encode("utf-8"))
            await writer.drain()
        except ValueError as exc:
            writer.write(self._json_response(400, {"ok": False, "message": str(exc)}).encode("utf-8"))
            await writer.drain()
        except asyncio.TimeoutError:
            writer.write(self._http_response(408, _CONTENT_TEXT, "Request Timeout").encode("utf-8"))
            await writer.drain()
        except Exception:
            logger.exception("SaaS service request failed")
            writer.write(self._json_response(500, {"ok": False, "message": "Internal server error"}).encode("utf-8"))
            await writer.drain()
        finally:
            writer.close()

    async def _read_request(self, reader: asyncio.StreamReader) -> Request:
        request_line = await asyncio.wait_for(reader.readline(), timeout=self.REQUEST_TIMEOUT)
        parts = request_line.decode(errors="replace").strip().split()
        if len(parts) < 2:
            raise ValueError("Malformed request line")
        method, raw_path = parts[0].upper(), parts[1]
        path = raw_path.split("?", 1)[0]

        headers: dict[str, str] = {}
        total_header_bytes = len(request_line)
        while True:
            header_line = await asyncio.wait_for(reader.readline(), timeout=self.REQUEST_TIMEOUT)
            total_header_bytes += len(header_line)
            if total_header_bytes > self.MAX_HEADER_BYTES:
                raise ValueError("Request headers too large")
            if header_line in (b"\r\n", b"\n", b""):
                break
            decoded = header_line.decode(errors="replace").strip()
            if ":" in decoded:
                key, value = decoded.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        body = b""
        if method == "POST":
            content_length = int(headers.get("content-length", "0"))
            if content_length > 65536:
                raise ValueError("Payload too large")
            if content_length:
                body = await asyncio.wait_for(reader.read(content_length), timeout=self.REQUEST_TIMEOUT)
        return Request(method=method, path=path, headers=headers, body=body)

    async def handle_request(self, request: Request) -> str:
        if request.method == "GET" and request.path in ("/", "/app"):
            return self._page_app()
        if request.path == "/health":
            return self._json_response(200, {"status": "ok", "mode": self.config.saas.mode})
        if request.method == "GET" and request.path == "/robots.txt":
            return self._robots_txt()
        if request.method == "GET" and request.path == "/.well-known/security.txt":
            return self._security_txt()
        if request.method == "GET" and request.path == "/google9d4cc8c07d77fbd5.html":
            return self._google_site_verification()
        if request.method == "POST" and request.path == "/api/v1/auth/signup":
            return self._signup(request)
        if request.method == "POST" and request.path == "/api/v1/auth/login":
            return self._login(request)
        if request.method == "GET" and request.path == "/api/v1/org":
            return self._get_org(request)
        if request.method == "POST" and request.path == "/api/v1/org/api-keys":
            return self._create_api_key(request)
        if request.method == "POST" and request.path == "/api/v1/billing/checkout-session":
            return self._create_checkout_session(request)
        if request.method == "POST" and request.path == "/api/v1/billing/portal-session":
            return self._create_portal_session(request)
        if request.method == "POST" and request.path == "/api/v1/billing/webhook":
            return self._billing_webhook(request)
        if request.method == "POST" and request.path == "/api/v1/fleet/register":
            return self._fleet_register(request)
        if request.method == "POST" and request.path == "/api/v1/fleet/report":
            return self._fleet_report(request)
        if request.method == "GET" and request.path == "/api/v1/fleet/agents":
            return self._fleet_agents(request)
        if request.method == "GET" and request.path == "/api/v1/fleet/reports":
            return self._fleet_reports(request)
        return self._json_response(404, {"ok": False, "message": "Not found"})

    def _page_app(self) -> str:
        return self._http_response(200, "text/html", get_saas_app_page())

    def _robots_txt(self) -> str:
        content = (
            "User-agent: *\n"
            "Allow: /\n"
            "Allow: /app\n"
            "Allow: /robots.txt\n"
            "Allow: /.well-known/security.txt\n"
            "\n"
            "# Network Guardian Cloud — Wolf-Pak Innovations LLC\n"
            "# Commercial cybersecurity monitoring platform\n"
            "# Source: https://github.com/Acquiredshot/Network-Guardian\n"
        )
        return self._http_response(200, "text/plain", content)

    def _security_txt(self) -> str:
        content = (
            "# Security contact for Network Guardian Cloud\n"
            "# Wolf-Pak Innovations LLC\n"
            "Contact: https://github.com/Acquiredshot/Network-Guardian/issues\n"
            "Preferred-Languages: en\n"
            "Canonical: https://network-guardian-cc8900c70290.herokuapp.com/.well-known/security.txt\n"
            "Policy: https://github.com/Acquiredshot/Network-Guardian/blob/main/LICENSE\n"
        )
        return self._http_response(200, "text/plain", content)

    def _google_site_verification(self) -> str:
        content = "google-site-verification: google9d4cc8c07d77fbd5.html\n"
        return self._http_response(200, "text/html", content)

    def _signup(self, request: Request) -> str:
        payload = self._json_body(request)
        org_name = str(payload.get("organization_name", "")).strip()
        org_slug = str(payload.get("organization_slug", "")).strip().lower()
        email = str(payload.get("email", "")).strip().lower()
        password = str(payload.get("password", ""))
        if not org_name or not org_slug or not email or not password:
            return self._json_response(400, {"ok": False, "message": "organization_name, organization_slug, email, and password are required"})
        password_hash = self._hash_password(password)
        try:
            organization, user, membership, _subscription = self.store.create_organization_with_owner(
                org_name=org_name,
                org_slug=org_slug,
                user_email=email,
                password_hash=password_hash,
            )
        except Exception as exc:
            return self._json_response(400, {"ok": False, "message": str(exc)})
        token = self._issue_token(user_id=user.id, organization_id=organization.id, role=membership.role)
        return self._json_response(
            201,
            {
                "ok": True,
                "token": token,
                "organization": {
                    "id": organization.id,
                    "name": organization.name,
                    "slug": organization.slug,
                    "plan": organization.plan,
                    "status": organization.status,
                },
                "user": {"id": user.id, "email": user.email, "role": membership.role},
            },
        )

    def _login(self, request: Request) -> str:
        payload = self._json_body(request)
        email = str(payload.get("email", "")).strip().lower()
        org_slug = str(payload.get("organization_slug", "")).strip().lower()
        password = str(payload.get("password", ""))
        if not email or not org_slug or not password:
            return self._json_response(400, {"ok": False, "message": "email, organization_slug, and password are required"})
        membership = self.store.get_membership_by_login(email=email, org_slug=org_slug)
        if membership is None:
            return self._json_response(403, {"ok": False, "message": "Invalid credentials"})
        if self._hash_password(password) != membership["password_hash"]:
            return self._json_response(403, {"ok": False, "message": "Invalid credentials"})
        token = self._issue_token(
            user_id=membership["user_id"],
            organization_id=membership["organization_id"],
            role=membership["role"],
        )
        return self._json_response(
            200,
            {
                "ok": True,
                "token": token,
                "organization": {
                    "id": membership["organization_id"],
                    "slug": membership["organization_slug"],
                    "name": membership["organization_name"],
                    "plan": membership["organization_plan"],
                    "status": membership["organization_status"],
                },
                "user": {"id": membership["user_id"], "email": membership["email"], "role": membership["role"]},
            },
        )

    def _get_org(self, request: Request) -> str:
        context = self._require_bearer_context(request)
        organization = self.store.get_organization(context.organization_id)
        if organization is None:
            return self._json_response(404, {"ok": False, "message": "Organization not found"})
        usage = self.store.get_usage_summary(context.organization_id)
        return self._json_response(200, {"ok": True, "organization": organization, "usage": usage})

    def _create_api_key(self, request: Request) -> str:
        context = self._require_bearer_context(request)
        require_role(context, "admin")
        payload = self._json_body(request)
        scope = str(payload.get("scope", "fleet:ingest")).strip() or "fleet:ingest"
        data = self.store.create_api_key(context.organization_id, scope=scope)
        return self._json_response(201, {"ok": True, **data})

    def _create_checkout_session(self, request: Request) -> str:
        context = self._require_bearer_context(request)
        payload = self._json_body(request)
        plan = str(payload.get("plan", "starter")).strip().lower()
        organization = self.store.get_organization(context.organization_id)
        user = self.store.get_user(context.user_id)
        if organization is None or user is None:
            return self._json_response(404, {"ok": False, "message": "Tenant context not found"})
        session = self.billing.create_checkout_session(
            organization_id=context.organization_id,
            organization_slug=organization["slug"],
            email=user["email"],
            plan=plan,
            success_url=self.config.saas.billing_success_url,
            cancel_url=self.config.saas.billing_cancel_url,
        )
        return self._json_response(
            201,
            {
                "ok": True,
                "provider": session.provider,
                "plan": session.plan,
                "session_id": session.session_id,
                "checkout_url": session.checkout_url,
            },
        )

    def _create_portal_session(self, request: Request) -> str:
        context = self._require_bearer_context(request)
        subscription = self.store.get_subscription(context.organization_id)
        if subscription is None:
            return self._json_response(404, {"ok": False, "message": "Subscription not found"})
        session = self.billing.create_portal_session(
            customer_id=subscription.get("provider_customer_id", ""),
            return_url=f"{self.config.saas.app_base_url}/app",
        )
        return self._json_response(201, {"ok": True, "provider": session.provider, "portal_url": session.portal_url})

    def _billing_webhook(self, request: Request) -> str:
        event = self.billing.verify_webhook(request.body, request.headers.get("stripe-signature", ""))
        event_type = event.get("type", "")
        data_object = ((event.get("data") or {}).get("object") or {})
        metadata = data_object.get("metadata") or {}
        organization_id = metadata.get("organization_id", "")
        plan = metadata.get("plan") or data_object.get("plan") or "starter"

        if event_type == "checkout.session.completed" and organization_id:
            self.store.update_subscription(
                organization_id=organization_id,
                plan=str(plan),
                status="active",
                provider_customer_id=str(data_object.get("customer", "")),
                provider_subscription_id=str(data_object.get("subscription", "")),
                current_period_end=str(data_object.get("current_period_end", "")) or None,
                billing_email=str(data_object.get("customer_email", "")),
            )
        elif event_type in ("customer.subscription.updated", "customer.subscription.deleted") and organization_id:
            status = str(data_object.get("status", "active"))
            if event_type == "customer.subscription.deleted":
                status = "canceled"
            price = ((data_object.get("items") or {}).get("data") or [{}])[0].get("price", {})
            self.store.update_subscription(
                organization_id=organization_id,
                plan=str(plan),
                status=status,
                provider_customer_id=str(data_object.get("customer", "")),
                provider_subscription_id=str(data_object.get("id", "")),
                current_period_end=str(data_object.get("current_period_end", "")) or None,
                billing_email=str(data_object.get("customer_email", "")),
                stripe_price_id=str(price.get("id", "")),
            )
        return self._json_response(200, {"ok": True, "received": True, "type": event_type})

    def _fleet_register(self, request: Request) -> str:
        api_key_record = self._require_api_key(request)
        payload = self._json_body(request)
        agent_id = str(payload.get("agent_id", "")).strip()
        if not agent_id:
            return self._json_response(400, {"ok": False, "message": "agent_id is required"})
        name = str(payload.get("name") or payload.get("label") or agent_id)
        platform = str(payload.get("platform", "unknown"))
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else payload
        agent = self.store.register_agent(
            organization_id=api_key_record["organization_id"],
            agent_id=agent_id,
            name=name,
            platform=platform,
            metadata=metadata,
        )
        return self._json_response(201, {"ok": True, "agent": agent})

    def _fleet_report(self, request: Request) -> str:
        api_key_record = self._require_api_key(request)
        payload = self._json_body(request)
        agent_id = str(payload.get("agent_id", "")).strip()
        if not agent_id:
            return self._json_response(400, {"ok": False, "message": "agent_id is required"})
        require_org_access(
            TenantContext(user_id="api-key", organization_id=api_key_record["organization_id"], role="admin"),
            api_key_record["organization_id"],
        )
        if self.store.get_agent(organization_id=api_key_record["organization_id"], agent_id=agent_id) is None:
            self.store.register_agent(
                organization_id=api_key_record["organization_id"],
                agent_id=agent_id,
                name=str(payload.get("name") or agent_id),
                platform=str(payload.get("platform", "unknown")),
                metadata=payload,
            )
        report = self.store.create_agent_report(
            organization_id=api_key_record["organization_id"],
            agent_id=agent_id,
            report=payload,
        )
        return self._json_response(202, {"ok": True, "report": report})

    def _fleet_agents(self, request: Request) -> str:
        context = self._require_bearer_context(request)
        agents = self.store.list_agents(context.organization_id)
        return self._json_response(200, {"ok": True, "agents": agents})

    def _fleet_reports(self, request: Request) -> str:
        context = self._require_bearer_context(request)
        reports = self.store.list_agent_reports(context.organization_id)
        return self._json_response(200, {"ok": True, "reports": reports})

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _issue_token(self, *, user_id: str, organization_id: str, role: str) -> str:
        return create_access_token(
            subject=user_id,
            org_id=organization_id,
            role=role,
            secret=self.config.saas.jwt_secret or "dev-secret-change-me",
            issuer=self.config.saas.jwt_issuer,
            audience=self.config.saas.jwt_audience,
            ttl_seconds=self.config.saas.access_token_ttl,
        )

    def _require_bearer_context(self, request: Request) -> TenantContext:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise TenancyError("Bearer token required")
        token = auth_header.split(" ", 1)[1].strip()
        claims = verify_access_token(
            token,
            secret=self.config.saas.jwt_secret or "dev-secret-change-me",
            issuer=self.config.saas.jwt_issuer,
            audience=self.config.saas.jwt_audience,
        )
        return TenantContext.from_claims(claims)

    def _require_api_key(self, request: Request) -> dict[str, Any]:
        api_key = request.headers.get("x-api-key", "").strip()
        if not api_key:
            raise TenancyError("API key required")
        record = self.store.get_api_key_record(api_key)
        if record is None:
            raise TenancyError("Invalid API key")
        return record

    def _json_body(self, request: Request) -> dict[str, Any]:
        if not request.body:
            return {}
        try:
            return json.loads(request.body)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON body") from exc

    def _json_response(self, status: int, payload: dict[str, Any]) -> str:
        return self._http_response(status, _CONTENT_JSON, json.dumps(payload))

    def _http_response(
        self,
        status: int,
        content_type: str,
        body: str,
        *,
        extra_headers: str = "",
    ) -> str:
        reason = {
            200: "OK",
            201: "Created",
            202: "Accepted",
            204: "No Content",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            408: "Request Timeout",
            500: "Internal Server Error",
        }.get(status, "OK")
        body_bytes = body.encode("utf-8")
        return (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: close\r\n"
            f"{extra_headers}"
            "\r\n"
            f"{body}"
        )
