# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Lateral Movement Detector.

Detects ransomware, worms, and internal recon by tracking each source IP's
connection fan-out (unique destination IPs) across rolling time windows.

How it works
------------
1. Every observed ``(src_ip, dst_ip)`` connection is recorded.
2. At the end of each window (default 5 minutes), the unique destination
   count for every source is archived into a per-IP history.
3. For each new observation the *current* fan-out is compared against the
   device's historical distribution.  If the z-score exceeds the spike
   threshold a ``LateralMovementAlert`` is returned.

Zero-day ransomware signature:
  - Normal device contacts 2-3 internal IPs per window
  - After compromise, it scans all /24 subnets → fan-out of 254+
  - Baseline mean=3, std=1  →  z-score = (254-3)/1 = 251  ✓ flagged

Persistence: graph history is saved to
    ~/.network_guardian/lateral_movement.json
"""

from __future__ import annotations

import collections
import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian.ai.lateral_movement")

# ---- tuneable knobs ----
_DEFAULT_WINDOW_SECONDS = 300     # 5-minute windows
_DEFAULT_SPIKE_Z = 3.0            # std-deviations above mean to alert
_DEFAULT_SPIKE_ABSOLUTE = 20      # also alert if fan-out exceeds this hard cap
_DEFAULT_MIN_PERIODS = 5          # baseline history periods required before alerting
_DEFAULT_MAX_HISTORY = 50         # max window periods kept per device


# ---------------------------------------------------------------------------
# Alert data-class
# ---------------------------------------------------------------------------


@dataclass
class LateralMovementAlert:
    """Raised when a source IP's connection fan-out spikes abnormally."""

    src_ip: str
    current_fanout: int              # unique dst IPs in current window
    baseline_mean: float             # average fan-out in historical windows
    baseline_std: float
    z_score: float                   # how many std-devs above mean
    is_alert: bool
    window_seconds: int
    dst_ips: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "current_fanout": self.current_fanout,
            "baseline_mean": round(self.baseline_mean, 2),
            "baseline_std": round(self.baseline_std, 2),
            "z_score": round(self.z_score, 2),
            "is_alert": self.is_alert,
            "window_seconds": self.window_seconds,
            "dst_ips": self.dst_ips[:20],   # cap to 20 for logging
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class LateralMovementDetector:
    """Tracks per-source connection fan-out and raises alerts on spikes.

    Thread-safety: not thread-safe; designed for single-threaded asyncio use.
    """

    def __init__(
        self,
        window_seconds: int = _DEFAULT_WINDOW_SECONDS,
        spike_z_threshold: float = _DEFAULT_SPIKE_Z,
        spike_absolute_threshold: int = _DEFAULT_SPIKE_ABSOLUTE,
        min_baseline_periods: int = _DEFAULT_MIN_PERIODS,
        max_history: int = _DEFAULT_MAX_HISTORY,
        data_dir: Path | None = None,
    ) -> None:
        self._window_seconds = window_seconds
        self._spike_z = spike_z_threshold
        self._spike_abs = spike_absolute_threshold
        self._min_periods = min_baseline_periods
        self._max_history = max_history
        self._data_dir = (
            data_dir if data_dir is not None
            else Path.home() / ".network_guardian"
        )

        # Current window state
        self._current_window: dict[str, set[str]] = collections.defaultdict(set)
        self._window_start: datetime = datetime.now(timezone.utc)

        # Historical fan-out counts: src_ip → deque of int
        self._history: dict[str, collections.deque[int]] = collections.defaultdict(
            lambda: collections.deque(maxlen=self._max_history)
        )

        # Counters
        self._total_connections: int = 0
        self._total_alerts: int = 0

        self._load()

    # -- Public API -----------------------------------------------------

    def observe_connection(
        self, src_ip: str, dst_ip: str
    ) -> LateralMovementAlert | None:
        """Record a connection and return an alert if lateral movement is detected.

        Returns ``None`` if no alert or baseline not yet established.
        """
        self._total_connections += 1
        now = datetime.now(timezone.utc)

        # Roll the window if the current one has expired
        elapsed = (now - self._window_start).total_seconds()
        if elapsed >= self._window_seconds:
            self._roll_window(now)

        self._current_window[src_ip].add(dst_ip)
        return self._score(src_ip, now)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_connections_observed": self._total_connections,
            "total_alerts_raised": self._total_alerts,
            "tracked_sources": len(self._history),
            "current_window_sources": len(self._current_window),
            "window_seconds": self._window_seconds,
        }

    def current_fanout(self, src_ip: str) -> int:
        """Return the current-window unique destination count for a source IP."""
        return len(self._current_window.get(src_ip, set()))

    def save(self) -> None:
        """Persist history to disk."""
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            path = self._data_dir / "lateral_movement.json"
            payload: dict[str, Any] = {
                "window_seconds": self._window_seconds,
                "history": {
                    ip: list(counts)
                    for ip, counts in self._history.items()
                },
            }
            path.write_text(json.dumps(payload, indent=2))
            logger.debug(
                "LateralMovementDetector: saved history for %d IPs to %s",
                len(self._history), path,
            )
        except OSError as exc:
            logger.warning("LateralMovementDetector: could not save: %s", exc)

    # -- Internal -------------------------------------------------------

    def _roll_window(self, now: datetime) -> None:
        """Archive current window counts into history and open a new window."""
        for src_ip, dst_set in self._current_window.items():
            self._history[src_ip].append(len(dst_set))
        self._current_window = collections.defaultdict(set)
        self._window_start = now
        logger.debug(
            "LateralMovementDetector: window rolled, %d sources archived",
            len(self._history),
        )

    def _score(self, src_ip: str, now: datetime) -> LateralMovementAlert | None:
        """Score the current fan-out for *src_ip* against its history."""
        history = self._history[src_ip]
        current = len(self._current_window[src_ip])

        # Not enough history for a statistical baseline yet — but still check
        # absolute threshold so brand-new devices aren't ignored.
        if len(history) < self._min_periods:
            if current >= self._spike_abs:
                alert = LateralMovementAlert(
                    src_ip=src_ip,
                    current_fanout=current,
                    baseline_mean=0.0,
                    baseline_std=0.0,
                    z_score=float("inf"),
                    is_alert=True,
                    window_seconds=self._window_seconds,
                    dst_ips=list(self._current_window[src_ip]),
                    timestamp=now,
                )
                self._total_alerts += 1
                logger.warning(
                    "LateralMovementDetector: ALERT (absolute) src=%s fanout=%d (no baseline yet)",
                    src_ip, current,
                )
                return alert
            return None

        counts = list(history)
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std = math.sqrt(variance)

        # z-score; guard against near-zero std
        if std < 0.5:
            # Device has very stable fan-out — use ratio instead
            z_score = current / max(mean, 1.0) - 1.0
        else:
            z_score = (current - mean) / std

        is_alert = z_score >= self._spike_z or current >= self._spike_abs

        result = LateralMovementAlert(
            src_ip=src_ip,
            current_fanout=current,
            baseline_mean=mean,
            baseline_std=std,
            z_score=z_score,
            is_alert=is_alert,
            window_seconds=self._window_seconds,
            dst_ips=list(self._current_window[src_ip]),
            timestamp=now,
        )

        if is_alert:
            self._total_alerts += 1
            logger.warning(
                "LateralMovementDetector: ALERT src=%s fanout=%d (mean=%.1f std=%.1f z=%.1f)",
                src_ip, current, mean, std, z_score,
            )

        return result

    def _load(self) -> None:
        """Load persisted history (non-fatal)."""
        path = self._data_dir / "lateral_movement.json"
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text())
            for ip, counts in payload.get("history", {}).items():
                dq: collections.deque[int] = collections.deque(
                    maxlen=self._max_history
                )
                dq.extend(counts[-self._max_history:])
                self._history[ip] = dq
            logger.info(
                "LateralMovementDetector: loaded history for %d IPs from %s",
                len(self._history), path,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("LateralMovementDetector: could not load history: %s", exc)
