import logging
import time
from typing import Any

import requests

from app.settings import settings

logger = logging.getLogger("security_event_pipeline.network_guardian")


class NetworkGuardianClient:
    """Pushes NSEP incidents into Network Guardian's Event Fabric intake endpoint.

    Envelope shape matches Network Guardian's public CrossAppEnvelope contract
    (see WOLF-PAK_CORRELATION_SPEC.md / scripts/mask_adapter.py in that repo).
    """

    def __init__(self) -> None:
        self.intake_url = settings.network_guardian_intake_url.rstrip("/")
        self.enabled = settings.network_guardian_enabled
        self.asset_id = settings.network_guardian_asset_id
        self.tenant_id = settings.network_guardian_tenant_id

    def push_incident(
        self,
        *,
        incident_id: str,
        event_id: str,
        source: str,
        event_type: str,
        severity: str,
        risk: int,
        detections: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if not self.enabled:
            logger.info("network_guardian_integration_disabled")
            return None

        envelope = {
            "timestamp_ms": int(time.time() * 1000),
            "asset_id": self.asset_id,
            "source": "NSEP",
            "source_version": "0.1.0",
            "event_type": "detection_event",
            "severity": severity.lower(),
            "category": "threat",
            "description": f"NSEP incident {incident_id} ({severity.upper()}) from {source}/{event_type}",
            "payload": {
                "incident_id": incident_id,
                "event_id": event_id,
                "source": source,
                "event_type": event_type,
                "risk_score": risk,
                "detections": detections,
            },
            "tenant_id": self.tenant_id,
        }

        try:
            response = requests.post(
                self.intake_url,
                json=envelope,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )

            if not response.ok:
                logger.error(
                    "network_guardian_push_failed",
                    extra={
                        "status_code": response.status_code,
                        "response_body": response.text[:1000],
                    },
                )
                return None

            data = response.json()

            if not data.get("ok"):
                logger.warning("network_guardian_push_rejected", extra={"response": data})
                return None

            logger.info(
                "network_guardian_event_pushed",
                extra={
                    "row_id": data.get("row_id"),
                    "graph_nodes": data.get("graph_nodes"),
                },
            )

            return data

        except requests.RequestException:
            logger.exception("network_guardian_push_failed")
            return None
