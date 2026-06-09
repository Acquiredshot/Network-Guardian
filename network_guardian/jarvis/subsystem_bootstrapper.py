"""
╔══════════════════════════════════════════════════════════════════╗
║  subsystem_bootstrapper.py  |  NG Launcher + Port Collision Mgr  ║
╠══════════════════════════════════════════════════════════════════╣
║  Responsibilities:                                               ║
║    1. Locate and validate the NG project root                    ║
║    2. Detect / resolve port 8080 collisions natively             ║
║    3. Launch start_all.py in a managed subprocess                ║
║    4. Gracefully shut down all NG-related processes              ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


# ══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════

def _resolve_ng_root() -> Path:
    """
    Auto-detect the Network Guardian project root.

    Priority:
      1. NG_ROOT environment variable
      2. Three levels up from this file  (…/network_guardian/jarvis/ → project root)
      3. Current working directory
    """
    env = os.environ.get("NG_ROOT", "")
    if env:
        return Path(env)
    # __file__ = …/network_guardian/jarvis/subsystem_bootstrapper.py
    # .parent.parent.parent = project root
    candidate = Path(__file__).resolve().parent.parent.parent
    if (candidate / "start_all.py").exists():
        return candidate
    return Path.cwd()


NG_ROOT            = _resolve_ng_root()
START_SCRIPT       = NG_ROOT / "start_all.py"
MANAGED_PORT       = int(os.environ.get("NG_PORT", "8080"))
STARTUP_WAIT_S     = 5
SHUTDOWN_WAIT_S    = 8

NG_PROCESS_SIGNATURES = (
    "start_all",
    "network_guardian",
    "network-guardian",
    "ng_server",
    "ng_api",
    "guardian",
)


# ══════════════════════════════════════════════════════════════════
# BOOTSTRAPPER
# ══════════════════════════════════════════════════════════════════

class SubsystemBootstrapper:
    """
    Manages the full lifecycle of Network Guardian subsystem processes.

    Usage
    -----
        bs = SubsystemBootstrapper()
        bs.launch()    # start defenses
        bs.shutdown()  # stop defenses
    """

    def __init__(self, ng_root: Path | None = None) -> None:
        self._ng_root    = ng_root or NG_ROOT
        self._start_script = self._ng_root / "start_all.py"
        self._proc: Optional[subprocess.Popen] = None

    # ── Public API ────────────────────────────────────────────────

    def launch(self) -> None:
        self._log("Validating environment...")
        self._validate_environment()
        self._log(f"Checking port {MANAGED_PORT} availability...")
        self._resolve_port_collision(MANAGED_PORT)
        self._log(f"Launching: {self._start_script}")
        self._proc = self._spawn_ng()
        self._log(f"Waiting {STARTUP_WAIT_S}s for subsystems to stabilise...")
        time.sleep(STARTUP_WAIT_S)
        if self._proc.poll() is not None:
            rc = self._proc.returncode
            raise RuntimeError(
                f"start_all.py exited immediately with return code {rc}. "
                "Check logs for startup errors."
            )
        self._log(
            f"Network Guardian is ONLINE  (PID {self._proc.pid}). "
            f"Listening on port {MANAGED_PORT}.",
            level="ok",
        )

    def shutdown(self) -> None:
        killed_any = False
        if self._proc and self._proc.poll() is None:
            self._log(f"Sending SIGTERM to managed process PID {self._proc.pid}...")
            self._proc.terminate()
            try:
                self._proc.wait(timeout=SHUTDOWN_WAIT_S)
                self._log(f"PID {self._proc.pid} exited cleanly.", level="ok")
                killed_any = True
            except subprocess.TimeoutExpired:
                self._log(
                    f"PID {self._proc.pid} did not exit within {SHUTDOWN_WAIT_S}s — force-killing.",
                    level="warn",
                )
                self._proc.kill()
                killed_any = True
            self._proc = None

        if _PSUTIL:
            for proc in _find_ng_processes():
                self._log(
                    f"Terminating orphaned NG process: {proc.name()} (PID {proc.pid})",
                    level="warn",
                )
                try:
                    proc.terminate()
                    proc.wait(timeout=SHUTDOWN_WAIT_S)
                    killed_any = True
                except Exception:
                    try:
                        proc.kill()
                        killed_any = True
                    except Exception:
                        pass

        self._release_port(MANAGED_PORT)
        if killed_any:
            self._log("All Network Guardian subsystems halted.", level="ok")
        else:
            self._log("No active Network Guardian processes found — already offline.", level="warn")

    @property
    def is_running(self) -> bool:
        """True if the managed subprocess is alive."""
        return self._proc is not None and self._proc.poll() is None

    # ── Internal helpers ──────────────────────────────────────────

    def _validate_environment(self) -> None:
        if not self._ng_root.exists():
            raise RuntimeError(
                f"Network Guardian root not found:\n  {self._ng_root}\n"
                "Set the NG_ROOT environment variable to override."
            )
        if not self._start_script.exists():
            raise RuntimeError(
                f"start_all.py not found at:\n  {self._start_script}\n"
                "Ensure the project structure is intact."
            )

    def _resolve_port_collision(self, port: int) -> None:
        if not _PSUTIL:
            self._log("psutil not installed — skipping port collision check.", level="warn")
            return
        holding = _processes_on_port(port)
        if not holding:
            self._log(f"Port {port} is free.", level="ok")
            return
        for proc in holding:
            try:
                name, pid = proc.name(), proc.pid
            except Exception:
                continue
            self._log(f"Port {port} held by '{name}' (PID {pid}). Releasing...", level="warn")
            try:
                proc.terminate()
                proc.wait(timeout=5)
                self._log(f"Released port {port} — PID {pid} terminated.", level="ok")
            except Exception as exc:
                self._log(f"Could not terminate PID {pid}: {exc}", level="warn")

    def _release_port(self, port: int) -> None:
        if not _PSUTIL:
            return
        for proc in _processes_on_port(port):
            try:
                proc.kill()
            except Exception:
                pass

    def _spawn_ng(self) -> subprocess.Popen:
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        return subprocess.Popen(
            [sys.executable, str(self._start_script)],
            cwd=str(self._ng_root),
            creationflags=flags,
        )

    @staticmethod
    def _log(msg: str, level: str = "info") -> None:
        ts    = datetime.now().strftime("%H:%M:%S")
        icons = {"info": "·", "ok": "✓", "warn": "⚠", "error": "✗"}
        print(f"  [BOOTSTRAP {ts}] {icons.get(level,'·')}  {msg}")


# ══════════════════════════════════════════════════════════════════
# PSUTIL HELPERS
# ══════════════════════════════════════════════════════════════════

def _processes_on_port(port: int) -> list:
    if not _PSUTIL:
        return []
    result = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                try:
                    result.append(psutil.Process(conn.pid))
                except Exception:
                    pass
    except Exception:
        pass
    return result


def _find_ng_processes() -> list:
    if not _PSUTIL:
        return []
    found = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            name    = (proc.info["name"] or "").lower()
            cmdline = " ".join(proc.info["cmdline"] or []).lower()
            if any(sig in name or sig in cmdline for sig in NG_PROCESS_SIGNATURES):
                found.append(proc)
        except Exception:
            pass
    return found
