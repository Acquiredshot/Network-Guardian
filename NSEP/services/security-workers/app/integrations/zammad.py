import logging
from typing import Any

import requests

from app.settings import settings

logger = logging.getLogger("security_event_pipeline.zammad")


class ZammadClient:
    def __init__(self) -> None:
        self.base_url = settings.zammad_url.rstrip("/")
        self.token = settings.zammad_api_token
        self.enabled = settings.zammad_enabled

    def create_ticket(
        self,
        *,
        title: str,
        article_body: str,
        priority_id: int,
        group_id: int | None = None,
        customer_id: int | None = None,
    ) -> dict[str, Any] | None:
        if not self.enabled:
            logger.info("zammad_integration_disabled")
            return None

        if not self.token:
            logger.warning("zammad_api_token_missing")
            return None

        payload = {
            "title": title,
            "group_id": settings.zammad_group_id if group_id is None else group_id,
            "priority_id": priority_id,
            "customer_id": settings.zammad_customer_id if customer_id is None else customer_id,
            "article": {
                "subject": title,
                "body": article_body,
                "content_type": "text/plain",
                "type": "note",
                "internal": False,
            },
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/v1/tickets",
                headers={
                    "Authorization": f"Token token={self.token}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=5,
            )

            if not response.ok:
                logger.error(
                    "zammad_ticket_creation_failed",
                    extra={
                        "status_code": response.status_code,
                        "response_body": response.text[:1000],
                    },
                )
                return None

            ticket = response.json()

            logger.info(
                "zammad_ticket_created",
                extra={
                    "ticket_id": ticket.get("id"),
                    "ticket_number": ticket.get("number"),
                },
            )

            return ticket

        except requests.RequestException:
            logger.exception("zammad_ticket_creation_failed")
            return None


def severity_to_priority(severity: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 3,
    }.get(severity.lower(), 2)
