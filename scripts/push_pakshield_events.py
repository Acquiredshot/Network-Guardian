#!/usr/bin/env python3
# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
push_pakshield_events.py — pushes PakShield-style identity risk / access
events to the Network Guardian Event Fabric intake endpoint.

This is the adapter that PakShield's Flask app would call (or a background
task in PakShield would enqueue) to forward risk scores and access findings
into the Wolf-Pak platform.

Usage:
    python push_pakshield_events.py [--url URL] [--count N]

Default URL: http://127.0.0.1:8080/api/event-fabric/intake
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("push_pakshield_events")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def post_intake(url: str, envelope: dict[str, Any]) -> dict[str, Any] | None:
    """POST a single CrossAppEnvelope to the NG intake endpoint."""
    try:
        resp = requests.post(url, json=envelope, timeout=10)
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            logger.info("  OK row=%s nodes=%s", data.get("row_id"), data.get("graph_nodes"))
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
# Event generators (mirrors of PakShield's risk / access models)
# ---------------------------------------------------------------------------

def make_risk_scored_envelope(
    user: str, risk_score: float, asset_id: str = "pakshield-tenant-01",
) -> dict[str, Any]:
    """Risk scored event — mirrors a PakShield RiskEvent being scored."""
    severity = "critical" if risk_score >= 0.8 else ("high" if risk_score >= 0.6 else
               ("medium" if risk_score >= 0.3 else "low"))
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "PAKSHIELD",
        "source_version": "1.0.0",
        "event_type": "risk_scored",
        "severity": severity,
        "category": "identity",
        "description": f"Risk score {risk_score:.2f} for identity {user}",
        "payload": {
            "native_risk_id": f"risk-{user}-{int(risk_score*100)}",
            "native_finding_id": f"finding-{user}-{int(risk_score*100)}",
            "user": user,
            "identity": user,
            "risk_score": risk_score,
            "risk_factors": [
                "impossible_travel" if risk_score > 0.6 else "none",
                "anomalous_login_time" if risk_score > 0.4 else "none",
                "new_device" if risk_score > 0.5 else "none",
            ],
            "tenant_id": "wolfpak-tenant-01",
        },
    }


def make_finding_created_envelope(
    user: str, title: str, severity: str, asset_id: str = "pakshield-tenant-01",
) -> dict[str, Any]:
    """Finding created event — mirrors a PakShield Finding being created."""
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "PAKSHIELD",
        "source_version": "1.0.0",
        "event_type": "finding_created",
        "severity": severity,
        "category": "identity",
        "description": f"Finding: {title} for {user}",
        "payload": {
            "native_finding_id": f"finding-{user}-{int(now_ms() % 100000)}",
            "native_risk_id": f"risk-{user}-{int(now_ms() % 10000)}",
            "user": user,
            "identity": user,
            "title": title,
            "finding_type": "anomalous_behavior",
            "confidence": 0.85,
            "tenant_id": "wolfpak-tenant-01",
        },
    }


def make_access_event_envelope(
    user: str, action: str, resource: str, allowed: bool,
    asset_id: str = "pakshield-tenant-01",
) -> dict[str, Any]:
    """Access event — mirrors a PakShield AccessEvent."""
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "PAKSHIELD",
        "source_version": "1.0.0",
        "event_type": "access_decision",
        "severity": "info" if allowed else "medium",
        "category": "auth",
        "description": f"{'Allowed' if allowed else 'Denied'}: {user} {action} {resource}",
        "payload": {
            "native_access_id": f"access-{user}-{int(now_ms() % 100000)}",
            "user": user,
            "action": action,
            "resource": resource,
            "allowed": allowed,
            "policy_evaluated": "mfa_required" if not allowed else "standard",
            "tenant_id": "wolfpak-tenant-01",
        },
    }


def make_device_posture_envelope(
    device_id: str, posture_score: float, asset_id: str = "pakshield-tenant-01",
) -> dict[str, Any]:
    """Device posture event — mirrors a PakShield device posture observation."""
    severity = "high" if posture_score < 0.5 else ("medium" if posture_score < 0.8 else "low")
    return {
        "timestamp_ms": now_ms(),
        "asset_id": asset_id,
        "source": "PAKSHIELD",
        "source_version": "1.0.0",
        "event_type": "device_posture_observation",
        "severity": severity,
        "category": "device",
        "description": f"Device posture score {posture_score:.2f} for {device_id}",
        "payload": {
            "native_device_id": device_id,
            "device_id": device_id,
            "posture_score": posture_score,
            "os": "Windows 11 Pro",
            "os_version": "23H2",
            "is_compliant": posture_score >= 0.8,
            "missing_patches": 3 if posture_score < 0.7 else 0,
            "antivirus_active": True,
            "firewall_enabled": True,
            "disk_encryption": True,
            "tenant_id": "wolfpak-tenant-01",
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

EVENT_TYPES = [
    ("risk", make_risk_scored_envelope),
    ("finding", make_finding_created_envelope),
    ("access", make_access_event_envelope),
    ("posture", make_device_posture_envelope),
]

# Sample identities (mirrors PakShield's seed data)
USERS = ["jdoe", "asmith", "mwilson", "rbrown", "tgarcia"]
# Sample devices
DEVICES = ["cody-wkstn-01", "lab-pc-02", "admin-macbook-pro"]


def make_risk_for_user(user: str) -> dict[str, Any]:
    """Vary risk by user for a realistic demo."""
    scores = {
        "jdoe": 0.92,    # critical — impossible travel + new device
        "asmith": 0.71,  # high — anomalous login time
        "mwilson": 0.45, # medium — new device only
        "rbrown": 0.22,  # low — normal
        "tgarcia": 0.88, # critical — multiple factors
    }
    return make_risk_scored_envelope(user, scores.get(user, 0.5))


def make_finding_for_user(user: str) -> dict[str, Any]:
    """Vary findings by user."""
    findings = {
        "jdoe": ("Impossible travel detected from new geography", "critical"),
        "asmith": ("Login from unusual time (03:00 local)", "high"),
        "mwilson": ("First login from unrecognized device", "medium"),
        "rbrown": ("Normal access pattern", "low"),
        "tgarcia": ("Multiple risk factors triggered simultaneously", "critical"),
    }
    title, sev = findings.get(user, ("Unknown pattern", "medium"))
    return make_finding_created_envelope(user, title, sev)


def make_access_for_user(user: str) -> dict[str, Any]:
    """Vary access decisions by user."""
    allowed_map = {
        "jdoe": False,   # denied — requires step-up MFA
        "asmith": True,  # allowed — standard
        "mwilson": True, # allowed — standard
        "rbrown": True,  # allowed — standard
        "tgarcia": False,# denied — requires step-up MFA
    }
    return make_access_event_envelope(
        user, "access_sensitive_resource", "/api/v1/financials", allowed_map.get(user, True),
    )


def run(url: str, count: int) -> int:
    """Push *count* batches and report."""
    ok = 0
    for batch in range(count):
        for user in USERS:
            # Risk + finding + access per user per batch
            envs = [
                ("risk", make_risk_for_user(user)),
                ("finding", make_finding_for_user(user)),
                ("access", make_access_for_user(user)),
            ]
            for label, env in envs:
                env["description"] = f"batch-{batch} {label} for {user}"
                result = post_intake(url, env)
                if result:
                    ok += 1
                time.sleep(0.03)

        # Device posture for 3 devices per batch
        for device in DEVICES:
            posture_score = 0.95 if device == "admin-macbook-pro" else (
                0.62 if device == "lab-pc-02" else 0.88)
            env = make_device_posture_envelope(device, posture_score)
            env["description"] = f"batch-{batch} posture for {device}"
            result = post_intake(url, env)
            if result:
                ok += 1
            time.sleep(0.03)

        logger.info("Batch %d complete (%d events OK)", batch + 1, ok)
        time.sleep(0.25)

    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description="Push PakShield-style identity events to NG Event Fabric")
    ap.add_argument("--url", default="http://127.0.0.1:8080/api/event-fabric/intake",
                    help="NG intake endpoint URL (default: %(default)s)")
    ap.add_argument("--count", type=int, default=2,
                    help="Number of batches to push (default: %(default)s)")
    ap.add_argument("--once", action="store_true",
                    help="Push a single batch and exit (for quick smoke test)")
    args = ap.parse_args()

    logger.info("Pushing PakShield identity events to %s", args.url)

    count = 1 if args.once else args.count
    ok = run(args.url, count)
    total = count * (len(USERS) * 3 + len(DEVICES))
    logger.info("Done: %d/%d events accepted", ok, total)

    if ok < total:
        logger.warning("Some events were rejected — check dashboard logs")
        sys.exit(1)


if __name__ == "__main__":
    main()
