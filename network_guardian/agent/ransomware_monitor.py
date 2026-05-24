"""
Network Guardian — Real-Time Ransomware Monitor

Watches a directory tree for ransomware activity using two heuristics:
  1. Files created/modified with known ransomware extensions
  2. Burst activity — N+ file events within a short rolling window

Runs the watchdog Observer in a background thread so it is non-blocking
inside the asyncio event loop.  Publishes events on the Guardian event bus
so IDS/IPS and the dashboard can react automatically.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus

logger = logging.getLogger("network_guardian.agent.ransomware_monitor")

# ---------------------------------------------------------------------------
# Defaults — can be overridden when constructing RansomwareMonitor
# ---------------------------------------------------------------------------

DEFAULT_WATCH_FOLDER: str = os.path.expanduser("~/Documents")
DEFAULT_THRESHOLD: int = 10          # file events within the window
DEFAULT_WINDOW_SECS: float = 5.0     # rolling window size in seconds

RANSOM_EXTENSIONS: frozenset[str] = frozenset({
    ".locked", ".enc", ".crypto", ".crypt",
    ".wnry", ".zepto", ".cerber", ".locky",
    ".wncry", ".wcry", ".onion", ".r5a",
})


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

@dataclass
class RansomwareAlert:
    kind: str          # "extension" | "burst"
    path: str | None
    detail: str
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Watchdog handler (runs in watchdog thread)
# ---------------------------------------------------------------------------

class _RansomwareHandler:
    """
    Minimal FileSystemEventHandler replacement that does not require watchdog
    to be imported at module load time (imported lazily inside the monitor).
    """

    def __init__(self, monitor: "RansomwareMonitor") -> None:
        self._monitor = monitor

    # ---- watchdog callbacks ------------------------------------------------

    def on_modified(self, event: object) -> None:
        if not getattr(event, "is_directory", True):
            self._check(getattr(event, "src_path", ""))

    def on_created(self, event: object) -> None:
        if not getattr(event, "is_directory", True):
            self._check(getattr(event, "src_path", ""))

    # ---- heuristic checks --------------------------------------------------

    def _check(self, path: str) -> None:
        self._check_extension(path)
        self._check_burst(path)

    def _check_extension(self, path: str) -> None:
        ext = os.path.splitext(path)[-1].lower()
        if ext in RANSOM_EXTENSIONS:
            alert = RansomwareAlert(
                kind="extension",
                path=path,
                detail=f"Ransomware extension '{ext}' detected: {path}",
            )
            self._monitor._on_alert(alert)

    def _check_burst(self, path: str) -> None:
        now = time.time()
        times = self._monitor._event_times
        times.append(now)
        # Evict events older than the rolling window
        while times and now - times[0] > self._monitor.window_secs:
            times.popleft()
        if len(times) >= self._monitor.threshold:
            alert = RansomwareAlert(
                kind="burst",
                path=None,
                detail=(
                    f"{len(times)} file events in {self._monitor.window_secs:.0f}s "
                    f"— possible ransomware encryption burst"
                ),
            )
            self._monitor._on_alert(alert)


# ---------------------------------------------------------------------------
# Public monitor class
# ---------------------------------------------------------------------------

class RansomwareMonitor:
    """Start/stop a background ransomware watchdog on a directory."""

    def __init__(
        self,
        event_bus: "EventBus | None" = None,
        watch_folder: str = DEFAULT_WATCH_FOLDER,
        threshold: int = DEFAULT_THRESHOLD,
        window_secs: float = DEFAULT_WINDOW_SECS,
    ) -> None:
        self.event_bus = event_bus
        self.watch_folder = watch_folder
        self.threshold = threshold
        self.window_secs = window_secs

        self._event_times: collections.deque[float] = collections.deque()
        self._observer: object | None = None      # watchdog Observer
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running = False
        self._lock = threading.Lock()
        self.alerts: list[RansomwareAlert] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start the watchdog observer in a background thread."""
        with self._lock:
            if self._running:
                return
            try:
                from watchdog.observers import Observer
                from watchdog.events import FileSystemEventHandler
            except ImportError:
                logger.error(
                    "watchdog is not installed. "
                    "Run: pip install watchdog"
                )
                return

            # Capture the running event loop for thread-safe event publishing
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = None

            # Build a proper watchdog FileSystemEventHandler by mixing in our handler
            handler_obj = _RansomwareHandler(self)

            class _WatchdogBridge(FileSystemEventHandler):
                def on_modified(self_, event):  # noqa: N805
                    handler_obj.on_modified(event)

                def on_created(self_, event):  # noqa: N805
                    handler_obj.on_created(event)

            observer = Observer()
            observer.schedule(
                _WatchdogBridge(),
                path=self.watch_folder,
                recursive=True,
            )
            observer.start()
            self._observer = observer
            self._running = True
            logger.info(
                "Ransomware monitor started: watching '%s' "
                "(threshold=%d events / %.0fs, %d ransomware extensions)",
                self.watch_folder,
                self.threshold,
                self.window_secs,
                len(RANSOM_EXTENSIONS),
            )

    def stop(self) -> None:
        """Stop the watchdog observer."""
        with self._lock:
            if not self._running or self._observer is None:
                return
            observer = self._observer
            self._observer = None
            self._running = False

        observer.stop()   # type: ignore[union-attr]
        observer.join()   # type: ignore[union-attr]
        logger.info("Ransomware monitor stopped.")

    # ------------------------------------------------------------------
    # Internal — called from watchdog thread
    # ------------------------------------------------------------------

    def _on_alert(self, alert: RansomwareAlert) -> None:
        self.alerts.append(alert)

        if alert.kind == "extension":
            logger.critical("[RANSOMWARE] %s", alert.detail)
            logger.critical("  Action: isolate this machine from the network NOW!")
        else:
            logger.critical("[RANSOMWARE BURST] %s", alert.detail)
            logger.critical("  Action: isolate this machine from the network NOW!")

        # Publish to the Guardian event bus from the watchdog thread safely
        if self.event_bus is not None and self._loop is not None:
            from network_guardian.core.events import Event
            asyncio.run_coroutine_threadsafe(
                self.event_bus.publish(Event(
                    topic="ransomware.alert",
                    data={
                        "kind": alert.kind,
                        "path": alert.path,
                        "detail": alert.detail,
                    },
                )),
                self._loop,
            )
