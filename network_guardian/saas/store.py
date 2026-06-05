from __future__ import annotations

import importlib.resources
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - optional in local test envs
    psycopg = None
    dict_row = None

from network_guardian.config import SaaSConfig
from network_guardian.saas.auth import generate_api_key, verify_api_key
from network_guardian.saas.models import Membership, Organization, Subscription, UsageEvent, User


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalise_database_url(database_url: str, data_dir: Path) -> Path | None:
    if not database_url:
        return data_dir / "saas.db"
    if database_url == ":memory:" or database_url.startswith("sqlite:///"):
        if database_url == ":memory:":
            return Path(":memory:")
        return Path(database_url.removeprefix("sqlite:///"))
    return None


def _database_backend(database_url: str) -> str:
    if not database_url or database_url == ":memory:" or database_url.startswith("sqlite:///"):
        return "sqlite"
    if database_url.startswith("postgresql://") or database_url.startswith("postgres://"):
        return "postgres"
    raise ValueError("DATABASE_URL must use sqlite:/// or postgresql://")


class SaaSStore:
    def __init__(self, config: SaaSConfig, data_dir: Path) -> None:
        self._database_url = config.database_url
        self._backend = _database_backend(config.database_url)
        self._db_path = _normalise_database_url(config.database_url, data_dir)

    @property
    def backend(self) -> str:
        return self._backend

    @contextmanager
    def connection(self) -> Iterator[Any]:
        if self._backend == "postgres":
            if psycopg is None:
                raise RuntimeError("psycopg is required for PostgreSQL DATABASE_URL values")
            conn = psycopg.connect(self._database_url, row_factory=dict_row)
        else:
            conn = sqlite3.connect(str(self._db_path))
            conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def migrate(self) -> None:
        migration_names = self._migration_names()
        with self.connection() as conn:
            self._execute_script(
                conn,
                "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);",
            )
            applied = {row["version"] if isinstance(row, dict) else row[0] for row in self._fetchall(conn, "SELECT version FROM schema_migrations")}
            for migration_name in migration_names:
                if migration_name in applied:
                    continue
                self._execute_script(conn, self._load_migration(migration_name))
                self._execute(
                    conn,
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (migration_name, _utcnow()),
                )

    def _migration_names(self) -> list[str]:
        files = importlib.resources.files("network_guardian.saas.migrations")
        return sorted(item.name.removesuffix(".sql") for item in files.iterdir() if item.name.endswith(".sql"))

    def _load_migration(self, migration_name: str) -> str:
        resource = importlib.resources.files("network_guardian.saas.migrations").joinpath(f"{migration_name}.sql")
        return resource.read_text(encoding="utf-8")

    def _placeholder_sql(self, sql: str) -> str:
        if self._backend != "postgres":
            return sql
        parts = sql.split("?")
        if len(parts) == 1:
            return sql
        rebuilt = [parts[0]]
        for index, part in enumerate(parts[1:], start=1):
            rebuilt.append(f"%s{part}")
        return "".join(rebuilt)

    def _execute(self, conn: Any, sql: str, params: tuple[Any, ...] = ()) -> Any:
        return conn.execute(self._placeholder_sql(sql), params)

    def _fetchall(self, conn: Any, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        return self._execute(conn, sql, params).fetchall()

    def _execute_script(self, conn: Any, script: str) -> None:
        if self._backend == "postgres":
            for statement in [chunk.strip() for chunk in script.split(";") if chunk.strip()]:
                self._execute(conn, statement)
            return
        conn.executescript(script)

    def create_organization_with_owner(
        self,
        *,
        org_name: str,
        org_slug: str,
        user_email: str,
        password_hash: str,
    ) -> tuple[Organization, User, Membership, Subscription]:
        organization = Organization(name=org_name, slug=org_slug)
        user = User(email=user_email, password_hash=password_hash)
        membership = Membership(
            organization_id=organization.id,
            user_id=user.id,
            role="owner",
        )
        subscription = Subscription(organization_id=organization.id)
        with self.connection() as conn:
            self._execute(
                conn,
                "INSERT INTO organizations(id, name, slug, plan, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    organization.id,
                    organization.name,
                    organization.slug,
                    organization.plan,
                    organization.status,
                    organization.created_at.isoformat(),
                    organization.updated_at.isoformat(),
                ),
            )
            self._execute(
                conn,
                "INSERT INTO users(id, email, password_hash, oidc_subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user.id,
                    user.email,
                    user.password_hash,
                    user.oidc_subject,
                    user.created_at.isoformat(),
                    user.updated_at.isoformat(),
                ),
            )
            self._execute(
                conn,
                "INSERT INTO memberships(id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    membership.id,
                    membership.organization_id,
                    membership.user_id,
                    membership.role,
                    membership.created_at.isoformat(),
                ),
            )
            self._execute(
                conn,
                "INSERT INTO subscriptions(id, organization_id, provider_customer_id, provider_subscription_id, plan, status, provider, current_period_end, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    subscription.id,
                    subscription.organization_id,
                    subscription.provider_customer_id,
                    subscription.provider_subscription_id,
                    subscription.plan,
                    subscription.status,
                    subscription.provider,
                    None,
                    subscription.created_at.isoformat(),
                    subscription.updated_at.isoformat(),
                ),
            )
        return organization, user, membership, subscription

    def get_membership_by_login(self, *, email: str, org_slug: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = self._execute(
                conn,
                """
                SELECT
                    u.id AS user_id,
                    u.email AS email,
                    u.password_hash AS password_hash,
                    o.id AS organization_id,
                    o.slug AS organization_slug,
                    o.name AS organization_name,
                    o.plan AS organization_plan,
                    o.status AS organization_status,
                    m.role AS role
                FROM users u
                JOIN memberships m ON m.user_id = u.id
                JOIN organizations o ON o.id = m.organization_id
                WHERE lower(u.email) = lower(?) AND o.slug = ?
                """,
                (email, org_slug),
            ).fetchone()
            return dict(row) if row else None

    def get_organization(self, organization_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = self._execute(
                conn,
                "SELECT id, name, slug, plan, status, created_at, updated_at FROM organizations WHERE id = ?",
                (organization_id,),
            ).fetchone()
            return dict(row) if row else None

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = self._execute(
                conn,
                "SELECT id, email, password_hash, oidc_subject, created_at, updated_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def create_api_key(self, organization_id: str, scope: str = "fleet:ingest") -> dict[str, str]:
        api_key, key_hash = generate_api_key()
        key_prefix = api_key.split(".", 1)[0]
        with self.connection() as conn:
            self._execute(
                conn,
                "INSERT INTO api_keys(id, organization_id, key_prefix, key_hash, scope, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key_prefix, organization_id, key_prefix, key_hash, scope, None, _utcnow()),
            )
        return {"api_key": api_key, "key_prefix": key_prefix, "scope": scope}

    def get_api_key_record(self, api_key: str) -> dict[str, Any] | None:
        key_prefix = api_key.split(".", 1)[0]
        with self.connection() as conn:
            row = self._execute(
                conn,
                "SELECT id, organization_id, key_prefix, key_hash, scope, revoked_at, created_at FROM api_keys WHERE key_prefix = ?",
                (key_prefix,),
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        if data.get("revoked_at"):
            return None
        if not verify_api_key(api_key, data["key_hash"]):
            return None
        return data

    def register_agent(
        self,
        *,
        organization_id: str,
        agent_id: str,
        name: str,
        platform: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        now = _utcnow()
        metadata_json = json.dumps(metadata, sort_keys=True)
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO agents(id, organization_id, name, platform, status, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    organization_id = excluded.organization_id,
                    name = excluded.name,
                    platform = excluded.platform,
                    status = excluded.status,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (agent_id, organization_id, name, platform, "active", metadata_json, now, now),
            )
        self.record_usage(organization_id=organization_id, metric="agents", quantity=1)
        return self.get_agent(organization_id=organization_id, agent_id=agent_id) or {}

    def get_agent(self, *, organization_id: str, agent_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = self._execute(
                conn,
                "SELECT id, organization_id, name, platform, status, metadata_json, created_at, updated_at FROM agents WHERE organization_id = ? AND id = ?",
                (organization_id, agent_id),
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["metadata"] = json.loads(data.pop("metadata_json"))
        return data

    def list_agents(self, organization_id: str) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = self._fetchall(
                conn,
                "SELECT id, organization_id, name, platform, status, metadata_json, created_at, updated_at FROM agents WHERE organization_id = ? ORDER BY updated_at DESC",
                (organization_id,),
            )
        agents = []
        for row in rows:
            data = dict(row)
            data["metadata"] = json.loads(data.pop("metadata_json"))
            agents.append(data)
        return agents

    def create_agent_report(self, *, organization_id: str, agent_id: str, report: dict[str, Any]) -> dict[str, Any]:
        now = _utcnow()
        report_id = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        with self.connection() as conn:
            self._execute(
                conn,
                "INSERT INTO agent_reports(id, agent_id, organization_id, report_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (report_id, agent_id, organization_id, json.dumps(report, sort_keys=True), now),
            )
            self._execute(
                conn,
                "UPDATE agents SET status = ?, updated_at = ? WHERE organization_id = ? AND id = ?",
                ("reporting", now, organization_id, agent_id),
            )
        self.record_usage(organization_id=organization_id, metric="reports", quantity=1)
        return {"id": report_id, "agent_id": agent_id, "organization_id": organization_id, "created_at": now}

    def list_agent_reports(self, organization_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = self._fetchall(
                conn,
                "SELECT id, agent_id, organization_id, report_json, created_at FROM agent_reports WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?",
                (organization_id, limit),
            )
        reports = []
        for row in rows:
            data = dict(row)
            data["report"] = json.loads(data.pop("report_json"))
            reports.append(data)
        return reports

    def record_usage(self, *, organization_id: str, metric: str, quantity: int) -> UsageEvent:
        event = UsageEvent(organization_id=organization_id, metric=metric, quantity=quantity)
        with self.connection() as conn:
            self._execute(
                conn,
                "INSERT INTO usage_events(id, organization_id, metric, quantity, occurred_at) VALUES (?, ?, ?, ?, ?)",
                (event.id, event.organization_id, event.metric, event.quantity, event.occurred_at.isoformat()),
            )
        return event

    def get_usage_summary(self, organization_id: str) -> dict[str, int]:
        with self.connection() as conn:
            rows = self._fetchall(
                conn,
                "SELECT metric, COALESCE(SUM(quantity), 0) AS total FROM usage_events WHERE organization_id = ? GROUP BY metric",
                (organization_id,),
            )
        return {row["metric"]: int(row["total"]) for row in rows}

    def get_subscription(self, organization_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = self._execute(
                conn,
                "SELECT id, organization_id, provider_customer_id, provider_subscription_id, plan, status, provider, current_period_end, created_at, updated_at, stripe_price_id, billing_email FROM subscriptions WHERE organization_id = ?",
                (organization_id,),
            ).fetchone()
        return dict(row) if row else None

    def update_subscription(
        self,
        *,
        organization_id: str,
        plan: str,
        status: str,
        provider_customer_id: str = "",
        provider_subscription_id: str = "",
        current_period_end: str | None = None,
        billing_email: str = "",
        stripe_price_id: str = "",
    ) -> dict[str, Any]:
        now = _utcnow()
        with self.connection() as conn:
            self._execute(
                conn,
                """
                UPDATE subscriptions
                SET provider_customer_id = ?,
                    provider_subscription_id = ?,
                    plan = ?,
                    status = ?,
                    current_period_end = ?,
                    updated_at = ?,
                    billing_email = ?,
                    stripe_price_id = ?
                WHERE organization_id = ?
                """,
                (
                    provider_customer_id,
                    provider_subscription_id,
                    plan,
                    status,
                    current_period_end,
                    now,
                    billing_email,
                    stripe_price_id,
                    organization_id,
                ),
            )
            self._execute(
                conn,
                "UPDATE organizations SET plan = ?, status = ?, updated_at = ? WHERE id = ?",
                (plan, status, now, organization_id),
            )
        return self.get_subscription(organization_id) or {}
