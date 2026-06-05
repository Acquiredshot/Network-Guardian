from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

OrganizationPlan = Literal["starter", "growth", "enterprise"]
OrganizationStatus = Literal["trialing", "active", "past_due", "canceled"]
MembershipRole = Literal["owner", "admin", "analyst", "viewer"]
SubscriptionProvider = Literal["stripe"]


@dataclass(slots=True)
class Organization:
    name: str
    slug: str
    plan: OrganizationPlan = "starter"
    status: OrganizationStatus = "trialing"
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class User:
    email: str
    id: str = field(default_factory=lambda: str(uuid4()))
    password_hash: str = ""
    oidc_subject: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class Membership:
    organization_id: str
    user_id: str
    role: MembershipRole
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class Subscription:
    organization_id: str
    provider_customer_id: str = ""
    provider_subscription_id: str = ""
    plan: OrganizationPlan = "starter"
    status: OrganizationStatus = "trialing"
    provider: SubscriptionProvider = "stripe"
    id: str = field(default_factory=lambda: str(uuid4()))
    current_period_end: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class APIKey:
    organization_id: str
    key_prefix: str
    key_hash: str
    scope: str = "fleet:ingest"
    id: str = field(default_factory=lambda: str(uuid4()))
    revoked_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class UsageEvent:
    organization_id: str
    metric: str
    quantity: int
    id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
