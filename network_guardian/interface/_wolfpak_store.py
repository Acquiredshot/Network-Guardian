"""Wolfpak Admin Client Store — server-side tracking of admin devices.

The base station tracks every wolfpak admin CLI tool connection by reading
three headers injected by WolfpakClient:
    X-WP-Tag    — unique device tag (24-char hex)
    X-WP-Client — tool name (ng-fleet, ng-ids, ng-status, …)
    X-WP-Host   — device hostname

The store is in-memory and survives for the life of the server process.
It exposes a JSON-serialisable list for the /api/wolfpak/clients endpoint.
"""

from __future__ import annotations

import time
from typing import Any


class WolfpakClientStore:
    """Registry of wolfpak admin client devices."""

    # Consider a client 'active' if seen within this many seconds
    ACTIVE_WINDOW = 5 * 60     # 5 minutes
    RECENT_WINDOW = 24 * 3600  # 24 hours (keep records this long)

    def __init__(self) -> None:
        # tag -> record dict
        self._clients: dict[str, dict[str, Any]] = {}

    # ── write ─────────────────────────────────────────────────────────────

    def record(
        self,
        tag: str,
        host: str,
        tool: str,
        username: str,
        path: str,
        client_ip: str,
    ) -> None:
        """Record or update a client connection."""
        if not tag:
            return
        now = time.time()
        if tag not in self._clients:
            self._clients[tag] = {
                "tag":           tag,
                "host":          host,
                "tool":          tool,
                "username":      username,
                "ip":            client_ip,
                "last_path":     path,
                "first_seen":    now,
                "last_seen":     now,
                "request_count": 0,
            }
        c = self._clients[tag]
        c["last_seen"]     = now
        c["last_path"]     = path
        c["ip"]            = client_ip
        c["tool"]          = tool
        c["username"]      = username
        # update hostname if provided (may change between reboots of same tag)
        if host:
            c["host"] = host
        c["request_count"] = c.get("request_count", 0) + 1

    # ── read ──────────────────────────────────────────────────────────────

    def list_clients(self) -> list[dict[str, Any]]:
        """Return all clients as JSON-safe list, newest first."""
        now = time.time()
        # Prune very old records to keep memory tidy
        self._prune(now)
        result = []
        for c in self._clients.values():
            last = c.get("last_seen", 0)
            result.append({
                "tag":           c["tag"],
                "host":          c.get("host", ""),
                "tool":          c.get("tool", ""),
                "username":      c.get("username", ""),
                "ip":            c.get("ip", ""),
                "last_path":     c.get("last_path", ""),
                "first_seen_ts": c.get("first_seen", 0),
                "last_seen_ts":  last,
                "request_count": c.get("request_count", 0),
                "active":        (now - last) < self.ACTIVE_WINDOW,
            })
        return sorted(result, key=lambda x: x["last_seen_ts"], reverse=True)

    def active_count(self) -> int:
        now = time.time()
        return sum(
            1 for c in self._clients.values()
            if (now - c.get("last_seen", 0)) < self.ACTIVE_WINDOW
        )

    def total_count(self) -> int:
        return len(self._clients)

    # ── maintenance ───────────────────────────────────────────────────────

    def _prune(self, now: float) -> None:
        """Remove records older than RECENT_WINDOW."""
        stale = [
            tag for tag, c in self._clients.items()
            if (now - c.get("last_seen", 0)) > self.RECENT_WINDOW
        ]
        for tag in stale:
            del self._clients[tag]
