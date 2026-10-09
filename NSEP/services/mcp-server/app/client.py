import logging
from typing import Any

import httpx

from app.settings import settings

logger = logging.getLogger("nsep_mcp.client")


class NSEPClientError(Exception):
    """Raised when the NSEP ingestion-api returns an unexpected error."""


class NSEPClient:
    """Thin read-only HTTP client over NSEP's existing ingestion-api endpoints.

    This intentionally does not implement any detection, risk, or incident
    logic itself -- it only calls the API that already exists.
    """

    def __init__(self) -> None:
        self._client = httpx.Client(
            base_url=settings.nsep_api_base_url.rstrip("/"),
            timeout=settings.request_timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, *, params: dict[str, Any] | None = None) -> Any | None:
        try:
            response = self._client.get(path, params=params)
        except httpx.RequestError as exc:
            raise NSEPClientError(f"NSEP API unreachable: GET {path}: {exc}") from exc

        if response.status_code == 404:
            return None

        if response.is_error:
            raise NSEPClientError(
                f"NSEP API error: GET {path} -> {response.status_code}: {response.text[:500]}"
            )

        return response.json()

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        return self._get(f"/api/v1/events/{event_id}")

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        return self._get(f"/api/v1/incidents/{incident_id}")

    def list_events(self, **params: Any) -> dict[str, Any]:
        result = self._get("/api/v1/events", params={k: v for k, v in params.items() if v is not None})
        return result if result is not None else {"items": [], "total": 0, "limit": 0, "offset": 0}

    def list_detections(self, **params: Any) -> dict[str, Any]:
        result = self._get("/api/v1/detections", params={k: v for k, v in params.items() if v is not None})
        return result if result is not None else {"items": [], "total": 0, "limit": 0, "offset": 0}

    def get_incident_timeline(self, incident_id: str) -> list[dict[str, Any]] | None:
        return self._get(f"/api/v1/incidents/{incident_id}/timeline")

    def get_incident_graph(self, incident_id: str) -> dict[str, Any] | None:
        return self._get(f"/api/v1/incidents/{incident_id}/graph")
