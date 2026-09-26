#!/usr/bin/env python3
# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
pakshield_adapter.py — exports PakShield identity, risk, and access events
into the Wolf-Pak Event Fabric.

Queries the PakShield SQLite database (pakshield.db) for:
  - risk_events  → pushed as risk_scored events
  - findings     → pushed as finding_created events
  - access_events → pushed as access_decision events
  - devices      → pushed as device_posture_observation events

Each row is wrapped in the CrossAppEnvelope schema and POSTed to the
Network Guardian dashboard intake endpoint.

Usage:
    python pakshield_adapter.py [--url URL] [--db PATH] [--once]

Default DB: ../PakShield/pakshield.db  (relative to this script)
Default URL: http://127.0.0.1:8080/api/event-fabric/intake
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

from network_guardian.core.events import CrossAppEnvelope

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pakshield_adapter")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def iso_to_ms(iso: str) -> int:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        return now_ms()


def post_event(url: str, envelope: CrossAppEnvelope) -> dict[str, Any] | None:
    try:
        resp = requests.post(
            url,
            json=envelope.to_dict(),
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            logger.info(
                "  stored row=%s nodes=%s source=%s type=%s sev=%s",
                data.get("row_id"),
                data.get("graph_nodes"),
                envelope.source,
                envelope.event_type,
                envelope.severity,
            )
            return data
        logger.warning("  FAIL status=%d body=%s", resp.status_code, data)
        return None
    except requests.ConnectionError:
        logger.error("  Cannot connect to %s — is the dashboard running?", url)
        return None
    except Exception as exc:
        logger.error("  Request failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db_path() -> str:
    """Resolve PakShield DB path: env var, then relative to this script, then common locations."""
    env = os.environ.get("PAKSHIELD_DB_PATH")
    if env and os.path.isfile(env):
        return env
    # Relative to this script: ../PakShield/pakshield.db
    rel = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "PakShield", "pakshield.db")
    if os.path.isfile(rel):
        return rel
    # Absolute path on the user's machine
    abs_path = r"C:\Users\CodyC\PakShield\pakshield.db"
    if os.path.isfile(abs_path):
        return abs_path
    return rel  # return best guess even if missing (caller handles)


def fetch_rows(db_path: str, query: str, params: tuple = ()) -> list[dict[str, Any]]:
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        logger.error("DB query failed (%s): %s", db_path, exc)
        return []


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------

def make_risk_envelope(row: dict[str, Any]) -> CrossAppEnvelope:
    return CrossAppEnvelope(
        timestamp_ms=iso_to_ms(row.get("created_at", "")),
        asset_id=row.get("tenant_id", "pakshield-tenant-01"),
        source="PAKSHIELD",
        source_version="1.0.0",
        event_type="risk_scored",
        severity=row.get("severity", "info"),
        category="identity",
        description=row.get("title", "Risk event"),
        payload={
            "native_risk_id": row.get("id", ""),
            "user": row.get("identity_display_name", ""),
            "identity": row.get("identity_display_name", ""),
            "risk_score": row.get("risk_score", 0.0),
            "source": row.get("source", ""),
            "indicators": json.loads(row["indicators"]) if row.get("indicators") else {},
            "tenant_id": row.get("tenant_id", "wolfpak-tenant-01"),
        },
        tenant_id=row.get("tenant_id", "wolfpak-tenant-01"),
    )


def make_finding_envelope(row: dict[str, Any]) -> CrossAppEnvelope:
    return CrossAppEnvelope(
        timestamp_ms=iso_to_ms(row.get("created_at", "")),
        asset_id=row.get("tenant_id", "pakshield-tenant-01"),
        source="PAKSHIELD",
        source_version="1.0.0",
        event_type="finding_created",
        severity=row.get("severity", "info"),
        category="identity",
        description=row.get("title", "Finding"),
        payload={
            "native_finding_id": row.get("id", ""),
            "native_risk_id": row.get("risk_event_id", ""),
            "user": row.get("identity_display_name", ""),
            "identity": row.get("identity_display_name", ""),
            "title": row.get("title", ""),
            "category": row.get("category", ""),
            "confidence": row.get("confidence", 1.0),
            "status": row.get("status", ""),
            "recommendation": row.get("recommendation", ""),
            "tenant_id": row.get("tenant_id", "wolfpak-tenant-01"),
        },
        tenant_id=row.get("tenant_id", "wolfpak-tenant-01"),
    )


def make_access_envelope(row: dict[str, Any]) -> CrossAppEnvelope:
    outcome = row.get("outcome", "granted")
    severity = "medium" if outcome in ("denied", "granted_with_warning") else "low"
    return CrossAppEnvelope(
        timestamp_ms=iso_to_ms(row.get("recorded_at", "")),
        asset_id=row.get("tenant_id", "pakshield-tenant-01"),
        source="PAKSHIELD",
        source_version="1.0.0",
        event_type="access_decision",
        severity=severity,
        category="auth",
        description=f"{outcome}: {row.get('identity_display_name','?')} {row.get('action','?')} {row.get('resource_name','?')}",
        payload={
            "native_access_id": row.get("id", ""),
            "user": row.get("identity_display_name", ""),
            "identity": row.get("identity_display_name", ""),
            "action": row.get("action", ""),
            "resource": row.get("resource_name", ""),
            "resource_type": row.get("resource_type", ""),
            "outcome": outcome,
            "source_ip": row.get("source_ip", ""),
            "session_id": row.get("session_id", ""),
            "policy_decisions": json.loads(row["policy_decisions"]) if row.get("policy_decisions") else [],
            "context": json.loads(row["context"]) if row.get("context") else {},
            "tenant_id": row.get("tenant_id", "wolfpak-tenant-01"),
        },
        tenant_id=row.get("tenant_id", "wolfpak-tenant-01"),
    )


def make_device_envelope(row: dict[str, Any]) -> CrossAppEnvelope:
    posture = row.get("posture_score", 1.0)
    severity = "high" if posture < 0.5 else ("medium" if posture < 0.8 else "low")
    return CrossAppEnvelope(
        timestamp_ms=now_ms(),  # devices are static; use now
        asset_id=row.get("id", ""),
        source="PAKSHIELD",
        source_version="1.0.0",
        event_type="device_posture_observation",
        severity=severity,
        category="device",
        description=f"Device posture: {row.get('name','?')} ({row.get('device_type','?')}) score={posture:.2f}",
        payload={
            "native_device_id": row.get("id", ""),
            "device_id": row.get("id", ""),
            "name": row.get("name", ""),
            "device_type": row.get("device_type", ""),
            "os": row.get("os", ""),
            "os_version": row.get("os_version", ""),
            "hostname": row.get("hostname", ""),
            "ip_address": row.get("ip_address", ""),
            "platform": row.get("platform", "unknown"),
            "posture_score": posture,
            "compliance_status": row.get("compliance_status", "unknown"),
            "encrypted": bool(row.get("encrypted", 0)),
            "mfa_capable": bool(row.get("mfa_capable", 0)),
            "status": row.get("status", "active"),
            "tenant_id": row.get("tenant_id", "wolfpak-tenant-01"),
        },
        tenant_id=row.get("tenant_id", "wolfpak-tenant-01"),
    )


# ---------------------------------------------------------------------------
# Main export
# ---------------------------------------------------------------------------

def export_all(url: str, db_path: str, since_ms: int = 0) -> dict[str, int]:
    """Export all pending events from PakShield DB to the Event Fabric.
    Returns dict of event_type -> count pushed.
    """
    counts: dict[str, int] = {}
    host = os.path.basename(db_path)

    # 1. Risk events
    rows = fetch_rows(
        db_path,
        """SELECT
            re.id, re.tenant_id, re.source, re.severity, re.risk_score,
            re.title, re.description, re.indicators, re.created_at,
            i.display_name AS identity_display_name
        FROM risk_events re
        LEFT JOIN identities i ON re.identity_id = i.id
        WHERE CAST(strftime('%s', re.created_at) AS INTEGER) * 1000 >= ?
        ORDER BY re.created_at DESC""",
        (since_ms,),
    )
    logger.info("Risk events in DB: %d (since %d)", len(rows), since_ms)
    for row in rows:
        env = make_risk_envelope(row)
        if post_event(url, env):
            counts["risk_scored"] = counts.get("risk_scored", 0) + 1

    # 2. Findings
    rows = fetch_rows(
        db_path,
        """SELECT
            f.id, f.tenant_id, f.title, f.description, f.category,
            f.severity, f.confidence, f.status, f.recommendation, f.created_at,
            i.display_name AS identity_display_name, re.id AS risk_event_id,
            re.severity AS risk_severity
        FROM findings f
        LEFT JOIN identities i ON f.identity_id = i.id
        LEFT JOIN risk_events re ON f.risk_event_id = re.id
        ORDER BY f.created_at DESC""",
    )
    logger.info("Findings in DB: %d", len(rows))
    for row in rows:
        env = make_finding_envelope(row)
        if post_event(url, env):
            counts["finding_created"] = counts.get("finding_created", 0) + 1

    # 3. Access events
    rows = fetch_rows(
        db_path,
        """SELECT
            ae.id, ae.tenant_id, ae.action, ae.outcome, ae.source_ip,
            ae.session_id, ae.policy_decisions, ae.context, ae.recorded_at,
            i.display_name AS identity_display_name,
            r.name AS resource_name, r.resource_type,
            dev.name AS device_name
        FROM access_events ae
        LEFT JOIN identities i ON ae.identity_id = i.id
        LEFT JOIN resources r ON ae.resource_id = r.id
        LEFT JOIN devices dev ON ae.device_id = dev.id
        ORDER BY ae.recorded_at DESC""",
    )
    logger.info("Access events in DB: %d", len(rows))
    for row in rows:
        env = make_access_envelope(row)
        if post_event(url, env):
            counts["access_decision"] = counts.get("access_decision", 0) + 1

    # 4. Devices (posture)
    rows = fetch_rows(
        db_path,
        """SELECT id, tenant_id, name, device_type, os, os_version,
                  hostname, ip_address, platform, posture_score,
                  compliance_status, encrypted, mfa_capable, status
           FROM devices ORDER BY name""",
    )
    logger.info("Devices in DB: %d", len(rows))
    for row in rows:
        env = make_device_envelope(row)
        if post_event(url, env):
            counts["device_posture"] = counts.get("device_posture", 0) + 1

    return counts


def main() -> None:
    ap = argparse.ArgumentParser(description="Export PakShield identity/risk/access events to Wolf-Pak Event Fabric")
    ap.add_argument("--url", default="http://127.0.0.1:8080/api/event-fabric/intake",
                    help="NG intake endpoint (default: %(default)s)")
    ap.add_argument("--db", default=None,
                    help="Path to pakshield.db (default: auto-detect)")
    ap.add_argument("--once", action="store_true",
                    help="Run one export and exit")
    ap.add_argument("--interval", type=int, default=60,
                    help="Poll interval in seconds (default: %(default)s)")
    ap.add_argument("--since", type=int, default=0,
                    help="Only export events after this epoch ms (default: 0 = all)")
    args = ap.parse_args()

    db_path = args.db or get_db_path()
    if not os.path.isfile(db_path):
        logger.error("PakShield DB not found at %s — set PAKSHIELD_DB_PATH", db_path)
        sys.exit(1)

    logger.info("PakShield adapter starting — db=%s url=%s", db_path, args.url)

    while True:
        try:
            counts = export_all(args.url, db_path, since_ms=args.since)
            total = sum(counts.values())
            logger.info("Export complete: %s (total %d events)", counts, total)
        except Exception as exc:
            logger.error("Export failed: %s", exc)
        if args.once:
            sys.exit(0 if total > 0 else 1)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
