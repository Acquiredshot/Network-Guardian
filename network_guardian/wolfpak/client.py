# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
#!/usr/bin/env python3
"""Wolfpak Admin Client — shared HTTP client with device tagging.

Every wolfpak admin CLI tool imports this module.  On first run it:
  1. Generates a unique device tag (24-char hex + hostname) in ~/.ng_client/tag.json
  2. Prompts for admin credentials (admin/<password>) and saves the session token
  3. Attaches the device tag and tool name to every API request via headers

The base station reads these headers to track which admin devices are active.
The tag persists across restarts; the session expires after 8 hours and
re-prompts for credentials automatically.
"""

from __future__ import annotations

import getpass
import json
import platform
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colours (disabled automatically when piped / non-TTY)
# ─────────────────────────────────────────────────────────────────────────────

def _c(code: str) -> str:
    return f"\033[{code}m" if sys.stdout.isatty() else ""

R    = _c("0")
B    = _c("1")
DIM  = _c("2")
RED  = _c("31")
GRN  = _c("32")
YLW  = _c("33")
BLU  = _c("34")
MAG  = _c("35")
CYN  = _c("36")
BRED = _c("1;31")
BGRN = _c("1;32")
BYEL = _c("1;33")
BBLU = _c("1;34")
BMAG = _c("1;35")
BCYN = _c("1;36")

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

_CLIENT_DIR  = Path.home() / ".ng_client"
_TAG_FILE    = _CLIENT_DIR / "tag.json"
_SESS_FILE   = _CLIENT_DIR / "session.json"
_SESSION_TTL = 8 * 3600   # 8 hours


# ─────────────────────────────────────────────────────────────────────────────
# Device tag helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_tag() -> dict:
    """Return existing tag or create a new one."""
    if _TAG_FILE.exists():
        try:
            data = json.loads(_TAG_FILE.read_text())
            if "tag" in data:
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return _create_tag()


def _create_tag() -> dict:
    """Generate and persist a unique device tag."""
    _CLIENT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tag: dict[str, Any] = {
        "tag": secrets.token_hex(12),          # 24-char hex unique device ID
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "created": datetime.now(timezone.utc).isoformat(),
        "version": "1",
    }
    _TAG_FILE.write_text(json.dumps(tag, indent=2))
    _TAG_FILE.chmod(0o600)
    return tag


# ─────────────────────────────────────────────────────────────────────────────
# Session helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_session() -> dict | None:
    """Return cached session if still valid."""
    if not _SESS_FILE.exists():
        return None
    try:
        data = json.loads(_SESS_FILE.read_text())
        if time.time() - data.get("saved_at", 0) > _SESSION_TTL:
            _SESS_FILE.unlink(missing_ok=True)
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def _save_session(token: str, username: str) -> None:
    _CLIENT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    _SESS_FILE.write_text(json.dumps(
        {"token": token, "username": username, "saved_at": time.time()},
    ))
    _SESS_FILE.chmod(0o600)


# ─────────────────────────────────────────────────────────────────────────────
# WolfpakClient
# ─────────────────────────────────────────────────────────────────────────────

class WolfpakClient:
    """Authenticated HTTP client with device tagging.

    Used by all wolfpak admin CLI tools.  Every request includes:
      - Cookie: ng_session=<token>       (authentication)
      - X-WP-Tag: <24-char hex>          (device identity)
      - X-WP-Client: <tool-name>         (which tool is calling)
      - X-WP-Host: <hostname>            (human-readable device name)
    """

    def __init__(self, base_url: str, tool: str = "ng-admin"):
        self.base  = base_url.rstrip("/")
        self.tool  = tool
        self._tag_data = _load_tag()
        self._tag      = self._tag_data["tag"]
        self._session  = _load_session()
        self._username: str = (self._session or {}).get("username", "")

    # ── identity ──────────────────────────────────────────────────────────

    @property
    def tag_id(self) -> str:
        return self._tag

    @property
    def tag_short(self) -> str:
        """First 8 chars of the tag for compact display."""
        return self._tag[:8]

    @property
    def hostname(self) -> str:
        return self._tag_data.get("hostname", "unknown")

    @property
    def username(self) -> str:
        return self._username

    # ── authentication ────────────────────────────────────────────────────

    def ensure_auth(self) -> None:
        """Ensure a valid session; prompt for credentials if needed."""
        if self._session:
            return
        self._prompt_login()

    def _prompt_login(self) -> None:
        print(f"\n  {BMAG}🔐 Wolfpak Authentication{R}")
        print(f"  {DIM}Base:   {self.base}{R}")
        print(f"  {DIM}Device: {self.tag_short}@{self.hostname}{R}\n")
        username = input(f"  {B}Username:{R} ").strip()
        password = getpass.getpass(f"  {B}Password:{R} ")
        if not self.authenticate(username, password):
            print(f"\n  {BRED}✗ Authentication failed{R}\n")
            sys.exit(1)
        print(f"\n  {BGRN}✓ Authenticated as {username}{R}\n")

    def authenticate(self, username: str, password: str) -> bool:
        """POST credentials and store the returned session token."""
        try:
            ok, data = self._raw_post(
                "/api/auth/login",
                {"username": username, "password": password},
                include_session=False,
            )
            if not ok:
                return False
            token = data.get("session") or data.get("token", "")
            if not token:
                return False
            self._username = username
            self._session  = {"token": token, "username": username, "saved_at": time.time()}
            _save_session(token, username)
            return True
        except Exception:
            return False

    def logout(self) -> None:
        """Clear local session (server session may still be valid)."""
        self._session = None
        _SESS_FILE.unlink(missing_ok=True)

    # ── request helpers ───────────────────────────────────────────────────

    def get(self, path: str) -> Any:
        ok, data = self._raw_get(path)
        if not ok:
            self._handle_error(path, data)
        return data

    def post(self, path: str, payload: dict) -> Any:
        ok, data = self._raw_post(path, payload)
        if not ok:
            self._handle_error(path, data)
        return data

    def _handle_error(self, path: str, data: dict) -> None:
        code = data.get("_status_code", 0)
        if code in (401, 403):
            self._session = None
            _SESS_FILE.unlink(missing_ok=True)
            print(f"  {BYEL}⚠ Session expired — re-authenticating{R}")
            self._prompt_login()
            return
        msg = data.get("error", data.get("message", str(data)))
        print(f"  {BRED}✗ Request failed [{code}]: {msg}{R}")
        sys.exit(1)

    def _wp_headers(self) -> dict:
        return {
            "Content-Type":       "application/json",
            "X-Requested-With":   "XMLHttpRequest",
            "X-WP-Tag":           self._tag,
            "X-WP-Client":        self.tool,
            "X-WP-Host":          self.hostname,
        }

    def _raw_get(self, path: str) -> tuple[bool, Any]:
        url  = self.base + path
        hdrs = self._wp_headers()
        if self._session:
            hdrs["Cookie"] = f"ng_session={self._session['token']}"
        req = urllib.request.Request(url, headers=hdrs, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode()
                return True, json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            return False, self._parse_http_error(e)
        except (urllib.error.URLError, OSError) as e:
            return False, {"error": str(e), "_status_code": 0}

    def _raw_post(
        self,
        path: str,
        payload: dict,
        include_session: bool = True,
    ) -> tuple[bool, Any]:
        url  = self.base + path
        body = json.dumps(payload).encode()
        hdrs = self._wp_headers()
        if include_session and self._session:
            hdrs["Cookie"] = f"ng_session={self._session['token']}"
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode()
                return True, json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            return False, self._parse_http_error(e)
        except (urllib.error.URLError, OSError) as e:
            return False, {"error": str(e), "_status_code": 0}

    @staticmethod
    def _parse_http_error(e: urllib.error.HTTPError) -> dict:
        raw = e.read().decode() if e.fp else ""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            data = {"error": raw or str(e)}
        data["_status_code"] = e.code
        return data

    # ── display helpers ───────────────────────────────────────────────────

    def banner(self, title: str, subtitle: str = "") -> None:
        """Print a styled wolfpak tool banner."""
        ts  = datetime.now().strftime("%H:%M:%S")
        dev = f"{self.tag_short}@{self.hostname}"
        print()
        print(f"  {BMAG}◈ {B}{title}{R}")
        if subtitle:
            print(f"  {DIM}{subtitle}{R}")
        print(f"  {DIM}Base: {self.base}  ·  Client: {dev}  ·  {ts}{R}")
        print(f"  {DIM}{'─' * 62}{R}")

    @staticmethod
    def table_row(cols: list, widths: list, colors: list | None = None) -> str:
        """Format a table row with column widths."""
        parts = []
        for i, (col, w) in enumerate(zip(cols, widths)):
            col_s = str(col)
            c_on  = (colors[i] if colors and i < len(colors) else "") or ""
            c_off = R if c_on else ""
            parts.append(f"{c_on}{col_s:<{w}}{c_off}")
        return "  " + "  ".join(parts)

    @staticmethod
    def ago(ts: float | None) -> str:
        """Human-readable 'X ago' string."""
        if not ts:
            return "never"
        diff = time.time() - ts
        if diff < 60:
            return f"{int(diff)}s ago"
        if diff < 3600:
            return f"{int(diff // 60)}m ago"
        if diff < 86400:
            return f"{int(diff // 3600)}h ago"
        return f"{int(diff // 86400)}d ago"
