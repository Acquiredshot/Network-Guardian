"""
Dashboard — web-based interface for network visualisation.

Provides a lightweight async HTTP dashboard for:
- Real-time network topology visualisation
- System health monitoring
- Finding / alert browsing
- Task management

Built on aiohttp for minimal dependencies. In production, front this
with a proper reverse proxy (nginx / caddy).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus

import os

if TYPE_CHECKING:
    from network_guardian.core.engine import Engine

logger = logging.getLogger("network_guardian.interface.dashboard")

_CONTENT_TEXT = "text/plain"


# ---------------------------------------------------------------------------
# Data serialisation helpers
# ---------------------------------------------------------------------------


def _serialise(obj: Any) -> Any:
    """Make dataclass / datetime JSON-serialisable."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialise(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialise(v) for v in obj]
    if hasattr(obj, "value"):  # Enum
        return obj.value
    return obj


# ---------------------------------------------------------------------------
# Dashboard server
# ---------------------------------------------------------------------------


class Dashboard:
    """Lightweight async HTTP dashboard.

    Uses only the stdlib ``http.server``-style pattern over raw asyncio
    sockets so we have zero extra dependencies for the foundation layer.
    A production build should swap this for aiohttp or FastAPI.
    """

    # Security: max header bytes to read before rejecting (8 KB)
    MAX_HEADER_BYTES = 8192
    # Security: request read timeout in seconds
    REQUEST_TIMEOUT = 10.0
    # Security: rate-limit window (seconds) and max requests per IP
    RATE_LIMIT_WINDOW = 60.0
    RATE_LIMIT_MAX = 120

    # CSP nonce is regenerated each startup
    _csp_nonce: str = ""

    def __init__(self, engine: Engine, host: str = "127.0.0.1", port: int | None = None) -> None:
        self.engine = engine
        self.host = host
        self.port = port or int(os.environ.get("NG_DASHBOARD_PORT", "8080"))
        self._server: asyncio.Server | None = None
        self._recent_events: list[dict[str, Any]] = []
        self._api_key: str | None = None
        # Rate limiting: {ip: [timestamps]}
        self._rate_tracker: dict[str, list[float]] = {}

        import secrets
        self._api_key = os.environ.get(engine.config.security.api_key_env)
        Dashboard._csp_nonce = secrets.token_urlsafe(16)

        # Subscribe to key events for the live feed
        for topic in ("audit.finding", "monitor.anomaly", "ai.anomaly_detected",
                       "explorer.discovery_complete", "automator.task_complete"):
            engine.event_bus.subscribe(topic, self._capture_event)

    def _capture_event(self, event: Event) -> None:
        entry = {"topic": event.topic, "data": _serialise(event.data),
                 "timestamp": event.timestamp.isoformat()}
        self._recent_events.append(entry)
        # Keep only last 200 events in memory
        if len(self._recent_events) > 200:
            self._recent_events = self._recent_events[-200:]

    # -- HTTP handling --------------------------------------------------

    def _check_rate_limit(self, client_ip: str) -> bool:
        """Return True if the request should be rejected (rate exceeded)."""
        import time as _time
        now = _time.monotonic()
        window = self.RATE_LIMIT_WINDOW
        timestamps = self._rate_tracker.get(client_ip, [])
        # Prune old entries
        timestamps = [t for t in timestamps if now - t < window]
        timestamps.append(now)
        self._rate_tracker[client_ip] = timestamps
        return len(timestamps) > self.RATE_LIMIT_MAX

    def _check_auth(self, headers: dict[str, str]) -> bool:
        """Return True if the request is authenticated (or auth is not configured)."""
        if not self._api_key:
            return True  # No key configured — allow
        auth = headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip() == self._api_key
        # Also accept X-API-Key header
        return headers.get("x-api-key", "") == self._api_key

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_ip = "unknown"
        try:
            peername = writer.get_extra_info("peername")
            if peername:
                client_ip = peername[0]

            # Rate limiting
            if self._check_rate_limit(client_ip):
                writer.write(self._http_response(429, _CONTENT_TEXT, "Too Many Requests").encode())
                await writer.drain()
                logger.warning("Rate limit exceeded for %s", client_ip)
                return

            # Read request line with timeout
            request_line = await asyncio.wait_for(
                reader.readline(), timeout=self.REQUEST_TIMEOUT
            )
            parts = request_line.decode(errors="replace").strip().split()
            if len(parts) < 2:
                writer.close()
                return

            method, path = parts[0], parts[1]

            # Consume headers (with size limit)
            headers: dict[str, str] = {}
            total_header_bytes = len(request_line)
            while True:
                header_line = await asyncio.wait_for(
                    reader.readline(), timeout=self.REQUEST_TIMEOUT
                )
                total_header_bytes += len(header_line)
                if total_header_bytes > self.MAX_HEADER_BYTES:
                    writer.write(
                        self._http_response(431, _CONTENT_TEXT,
                                            "Request Header Fields Too Large").encode()
                    )
                    await writer.drain()
                    return
                if header_line in (b"\r\n", b"\n", b""):
                    break
                decoded = header_line.decode(errors="replace").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Reject non-GET methods
            if method.upper() not in ("GET", "HEAD"):
                writer.write(
                    self._http_response(405, _CONTENT_TEXT, "Method Not Allowed").encode()
                )
                await writer.drain()
                return

            # Authentication check for API routes
            if path.startswith("/api/") and not self._check_auth(headers):
                writer.write(
                    self._http_response(401, _CONTENT_TEXT, "Unauthorized").encode()
                )
                await writer.drain()
                logger.warning("Unauthorized API request from %s: %s %s", client_ip, method, path)
                return

            response = self._route(path)
            writer.write(response.encode())
            await writer.drain()
            logger.debug("Request from %s: %s %s", client_ip, method, path)
        except asyncio.TimeoutError:
            logger.debug("Request timeout for %s", client_ip)
        except Exception:
            logger.debug("Dashboard client error from %s", client_ip, exc_info=True)
        finally:
            writer.close()

    def _route(self, path: str) -> str:
        routes: dict[str, Any] = {
            "/": self._page_index,
            "/api/status": self._api_status,
            "/api/findings": self._api_findings,
            "/api/events": self._api_events,
            "/api/hosts": self._api_hosts,
            "/api/tasks": self._api_tasks,
            "/api/health": self._api_health,
        }

        handler = routes.get(path)
        if handler is None:
            return self._http_response(404, _CONTENT_TEXT, "Not Found")
        return handler()

    # -- API endpoints --------------------------------------------------

    def _api_status(self) -> str:
        data = {
            "engine_running": self.engine.is_running,
            "data_dir": str(self.engine.config.data_dir),
            "subsystems": {
                "auditor": self.engine._auditor is not None,
                "monitor": self.engine._monitor is not None,
                "explorer": self.engine._explorer is not None,
                "automator": self.engine._automator is not None,
            },
        }
        return self._json_response(data)

    def _api_findings(self) -> str:
        findings = self.engine.auditor.findings if self.engine._auditor else []
        return self._json_response([_serialise(f) for f in findings])

    def _api_events(self) -> str:
        return self._json_response(self._recent_events[-50:])

    def _api_hosts(self) -> str:
        hosts = self.engine.explorer.hosts if self.engine._explorer else {}
        return self._json_response({ip: _serialise(h) for ip, h in hosts.items()})

    def _api_tasks(self) -> str:
        tasks = self.engine.automator.list_tasks() if self.engine._automator else []
        history = self.engine.automator.history if self.engine._automator else []
        return self._json_response({
            "registered": [{"name": t.name, "description": t.description} for t in tasks],
            "history": [_serialise(r) for r in history[-20:]],
        })

    def _api_health(self) -> str:
        return self._json_response({"status": "ok", "engine_running": self.engine.is_running})

    # -- HTML page ------------------------------------------------------

    def _page_index(self) -> str:
        nonce = Dashboard._csp_nonce
        html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Network Guardian Dashboard</title>
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif;
           background:#0d1117; color:#c9d1d9; }}
    header {{ background:#161b22; padding:1rem 2rem; border-bottom:1px solid #30363d; }}
    header h1 {{ font-size:1.4rem; color:#58a6ff; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr));
            gap:1rem; padding:1.5rem; }}
    .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
            padding:1.2rem; }}
    .card h2 {{ font-size:1rem; color:#58a6ff; margin-bottom:.8rem; }}
    pre {{ background:#0d1117; padding:.8rem; border-radius:4px; overflow-x:auto;
          font-size:.85rem; max-height:300px; overflow-y:auto; }}
    .ok {{ color:#3fb950; }} .warn {{ color:#d29922; }} .err {{ color:#f85149; }}
    #refresh {{ cursor:pointer; background:#21262d; color:#c9d1d9;
               border:1px solid #30363d; padding:.4rem 1rem; border-radius:4px; }}
  </style>
</head>
<body>
  <header>
    <h1>&#128737; Network Guardian Dashboard</h1>
  </header>
  <div style="padding:1rem 2rem">
    <button id="refresh" onclick="loadAll()">Refresh</button>
  </div>
  <div class="grid">
    <div class="card"><h2>System Status</h2><pre id="status">Loading...</pre></div>
    <div class="card"><h2>Health</h2><pre id="health">Loading...</pre></div>
    <div class="card"><h2>Recent Findings</h2><pre id="findings">Loading...</pre></div>
    <div class="card"><h2>Discovered Hosts</h2><pre id="hosts">Loading...</pre></div>
    <div class="card"><h2>Live Events</h2><pre id="events">Loading...</pre></div>
    <div class="card"><h2>Tasks</h2><pre id="tasks">Loading...</pre></div>
  </div>
  <script nonce="{nonce}">
    async function load(id, url) {{
      try {{
        const r = await fetch(url);
        document.getElementById(id).textContent = JSON.stringify(await r.json(), null, 2);
      }} catch(e) {{ document.getElementById(id).textContent = 'Error: ' + e; }}
    }}
    function loadAll() {{
      load('status',   '/api/status');
      load('health',   '/api/health');
      load('findings', '/api/findings');
      load('hosts',    '/api/hosts');
      load('events',   '/api/events');
      load('tasks',    '/api/tasks');
    }}
    loadAll();
    setInterval(loadAll, 10000);
  </script>
</body>
</html>"""
        return self._http_response(200, "text/html", html)

    # -- Response helpers -----------------------------------------------

    # Security headers added to every response
    _SECURITY_HEADERS = (
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: strict-origin-when-cross-origin\r\n"
        "Permissions-Policy: geolocation=(), camera=(), microphone=()\r\n"
        "Cache-Control: no-store\r\n"
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"
    )

    @classmethod
    def _http_response(cls, status: int, content_type: str, body: str) -> str:
        reason = {
            200: "OK", 401: "Unauthorized", 404: "Not Found",
            405: "Method Not Allowed", 429: "Too Many Requests",
            431: "Request Header Fields Too Large",
            500: "Internal Server Error",
        }.get(status, "OK")
        csp = (
            f"Content-Security-Policy: default-src 'self'; "
            f"script-src 'nonce-{cls._csp_nonce}'; "
            f"style-src 'self' 'unsafe-inline'; "
            f"img-src 'self'; connect-src 'self'\r\n"
        )
        return (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Connection: close\r\n"
            f"{cls._SECURITY_HEADERS}"
            f"{csp}"
            f"\r\n"
            f"{body}"
        )

    @classmethod
    def _json_response(cls, data: Any) -> str:
        body = json.dumps(data, default=str)
        return cls._http_response(200, "application/json", body)

    # -- Server lifecycle -----------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info("Dashboard listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Dashboard stopped.")
