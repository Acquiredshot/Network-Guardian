from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

import requests

from network_guardian.config import SaaSConfig


class BillingError(ValueError):
    """Raised when billing operations fail."""


@dataclass(frozen=True, slots=True)
class CheckoutSession:
    session_id: str
    checkout_url: str
    provider: str
    plan: str


@dataclass(frozen=True, slots=True)
class PortalSession:
    portal_url: str
    provider: str


class StripeBilling:
    PLAN_PRICES = {
        "starter": 2900,
        "growth": 9900,
        "enterprise": 24900,
    }

    def __init__(self, config: SaaSConfig) -> None:
        self.config = config

    @property
    def enabled(self) -> bool:
        return bool(self.config.stripe_secret_key)

    def create_checkout_session(
        self,
        *,
        organization_id: str,
        organization_slug: str,
        email: str,
        plan: str,
        success_url: str,
        cancel_url: str,
    ) -> CheckoutSession:
        if plan not in self.PLAN_PRICES:
            raise BillingError(f"Unknown plan: {plan}")
        if not self.enabled:
            session_id = f"mock_cs_{secrets.token_hex(12)}"
            checkout_url = f"{success_url}?session_id={session_id}&plan={plan}"
            return CheckoutSession(
                session_id=session_id,
                checkout_url=checkout_url,
                provider="mock",
                plan=plan,
            )

        response = requests.post(
            "https://api.stripe.com/v1/checkout/sessions",
            auth=(self.config.stripe_secret_key, ""),
            data={
                "mode": "subscription",
                "success_url": success_url,
                "cancel_url": cancel_url,
                "customer_email": email,
                "line_items[0][price_data][currency]": "usd",
                "line_items[0][price_data][unit_amount]": str(self.PLAN_PRICES[plan]),
                "line_items[0][price_data][recurring][interval]": "month",
                "line_items[0][price_data][product_data][name]": f"Network Guardian {plan.title()}",
                "line_items[0][quantity]": "1",
                "metadata[organization_id]": organization_id,
                "metadata[organization_slug]": organization_slug,
                "metadata[plan]": plan,
            },
            timeout=15,
        )
        if response.status_code >= 300:
            raise BillingError(f"Stripe checkout creation failed: {response.text}")
        payload = response.json()
        return CheckoutSession(
            session_id=payload["id"],
            checkout_url=payload["url"],
            provider="stripe",
            plan=plan,
        )

    def create_portal_session(self, *, customer_id: str, return_url: str) -> PortalSession:
        if not customer_id:
            return PortalSession(portal_url=return_url, provider="mock")
        if not self.enabled:
            return PortalSession(portal_url=return_url, provider="mock")
        response = requests.post(
            "https://api.stripe.com/v1/billing_portal/sessions",
            auth=(self.config.stripe_secret_key, ""),
            data={
                "customer": customer_id,
                "return_url": return_url,
            },
            timeout=15,
        )
        if response.status_code >= 300:
            raise BillingError(f"Stripe portal creation failed: {response.text}")
        payload = response.json()
        return PortalSession(portal_url=payload["url"], provider="stripe")

    def verify_webhook(self, payload: bytes, signature_header: str) -> dict[str, Any]:
        if not payload:
            raise BillingError("Webhook payload is required")
        if not self.config.stripe_webhook_secret:
            return json.loads(payload)
        if not signature_header:
            raise BillingError("Stripe-Signature header required")
        parsed = self._parse_signature(signature_header)
        timestamp = parsed["t"]
        signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
        expected = hmac.new(
            self.config.stripe_webhook_secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        signatures = parsed.get("v1", [])
        if not any(hmac.compare_digest(sig, expected) for sig in signatures):
            raise BillingError("Invalid Stripe webhook signature")
        now = int(time.time())
        if abs(now - int(timestamp)) > 300:
            raise BillingError("Stale Stripe webhook timestamp")
        return json.loads(payload)

    def _parse_signature(self, header: str) -> dict[str, Any]:
        result: dict[str, Any] = {"v1": []}
        for chunk in header.split(","):
            key, _, value = chunk.partition("=")
            key = key.strip()
            value = value.strip()
            if not key or not value:
                continue
            if key == "v1":
                result.setdefault("v1", []).append(value)
            else:
                result[key] = value
        if "t" not in result or not result.get("v1"):
            raise BillingError("Malformed Stripe-Signature header")
        return result
