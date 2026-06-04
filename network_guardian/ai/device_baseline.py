# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Per-Device Persistent Behavioral Baselines.

Maintains a rolling window of feature observations per device (keyed by IP).
When enough samples are collected, an Isolation Forest is fitted for that
device and subsequent observations are scored against its *own* baseline —
not a fleet-wide average.

This catches slow drift and zero-day behavior changes that batch-fitting
would miss:
  - A device that normally opens 3 connections/min suddenly opens 500
  - An endpoint that never touches port 445 starts SMB scanning
  - A host whose CPU is always <10% spikes to 90% for hours

Persistence: histories are saved to
    ~/.network_guardian/baselines/<sanitised_device_id>.json
so baselines survive daemon restarts.
"""

from __future__ import annotations

import collections
import json
import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from network_guardian.ai.anomaly import AnomalyScore, IsolationForest

logger = logging.getLogger("network_guardian.ai.device_baseline")

# Minimum observations before the detector is fitted for the first time
_MIN_SAMPLES_DEFAULT = 30

# How often to refit (every N new observations after the initial fit)
_REFIT_EVERY = 10

# Rolling window size per device
_WINDOW_SIZE_DEFAULT = 200


# ---------------------------------------------------------------------------
# Single device baseline
# ---------------------------------------------------------------------------


class DeviceBaseline:
    """Rolling behavioral baseline for one device."""

    def __init__(
        self,
        device_id: str,
        window_size: int = _WINDOW_SIZE_DEFAULT,
        min_samples: int = _MIN_SAMPLES_DEFAULT,
    ) -> None:
        self.device_id = device_id
        self._window_size = window_size
        self._min_samples = min_samples
        self._history: collections.deque[list[float]] = collections.deque(
            maxlen=window_size
        )
        self._detector: IsolationForest | None = None
        self._fitted_at: datetime | None = None
        self._observation_count: int = 0
        self._anomaly_count: int = 0

    # -- Public API -----------------------------------------------------

    def observe(self, features: list[float]) -> AnomalyScore | None:
        """Record a feature vector and return an anomaly score if fitted.

        Returns ``None`` until ``min_samples`` observations have been
        collected (no false positives during warm-up).
        """
        self._history.append(list(features))
        self._observation_count += 1

        # Fit initially, then refit every _REFIT_EVERY new points
        enough = len(self._history) >= self._min_samples
        should_refit = (
            self._detector is None
            or self._observation_count % _REFIT_EVERY == 0
        )
        if enough and should_refit:
            self._refit()

        if self._detector is None:
            return None

        result = self._detector.score(features)
        if result.is_anomaly:
            self._anomaly_count += 1
        return result

    @property
    def is_fitted(self) -> bool:
        return self._detector is not None

    @property
    def observation_count(self) -> int:
        return self._observation_count

    def get_stats(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "observations": self._observation_count,
            "anomalies": self._anomaly_count,
            "history_len": len(self._history),
            "fitted": self.is_fitted,
            "fitted_at": self._fitted_at.isoformat() if self._fitted_at else None,
        }

    # -- Persistence ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "window_size": self._window_size,
            "min_samples": self._min_samples,
            "history": list(self._history),
            "observation_count": self._observation_count,
            "anomaly_count": self._anomaly_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceBaseline":
        obj = cls(
            device_id=data["device_id"],
            window_size=data.get("window_size", _WINDOW_SIZE_DEFAULT),
            min_samples=data.get("min_samples", _MIN_SAMPLES_DEFAULT),
        )
        for row in data.get("history", []):
            obj._history.append(row)
        obj._observation_count = data.get("observation_count", len(obj._history))
        obj._anomaly_count = data.get("anomaly_count", 0)
        # Re-fit on loaded history if enough data
        if len(obj._history) >= obj._min_samples:
            obj._refit()
        return obj

    # -- Internal -------------------------------------------------------

    def _refit(self) -> None:
        data = list(self._history)
        n_trees = min(50, max(10, len(data) // 5))
        max_samples = min(len(data), 128)
        self._detector = IsolationForest(
            n_trees=n_trees, max_samples=max_samples, seed=42
        )
        self._detector.fit(data)
        self._fitted_at = datetime.now(timezone.utc)
        logger.debug(
            "DeviceBaseline refitted: device=%s observations=%d n_trees=%d",
            self.device_id, self._observation_count, n_trees,
        )


# ---------------------------------------------------------------------------
# Manager — owns all per-device baselines + disk persistence
# ---------------------------------------------------------------------------


def _safe_filename(device_id: str) -> str:
    """Turn an IP or hostname into a safe filename."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", device_id) + ".json"


class DeviceBaselineManager:
    """Manages per-device rolling baselines with disk persistence.

    Usage::

        manager = DeviceBaselineManager()
        score = manager.observe("192.168.1.42", [conn_rate, cpu, open_ports])
        if score and score.is_anomaly:
            print(f"Anomaly on 192.168.1.42 — score {score.score:.2f}")
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        window_size: int = _WINDOW_SIZE_DEFAULT,
        min_samples: int = _MIN_SAMPLES_DEFAULT,
    ) -> None:
        self._baselines: dict[str, DeviceBaseline] = {}
        self._data_dir = (
            data_dir if data_dir is not None
            else Path.home() / ".network_guardian" / "baselines"
        )
        self._window_size = window_size
        self._min_samples = min_samples
        self._load()

    # -- Public API -----------------------------------------------------

    def observe(self, device_id: str, features: list[float]) -> AnomalyScore | None:
        """Record features for a device and return its anomaly score (or None during warm-up)."""
        if device_id not in self._baselines:
            self._baselines[device_id] = DeviceBaseline(
                device_id, self._window_size, self._min_samples
            )
            logger.info("DeviceBaseline: new device registered — %s", device_id)
        return self._baselines[device_id].observe(features)

    def get_baseline(self, device_id: str) -> DeviceBaseline | None:
        return self._baselines.get(device_id)

    def get_stats(self) -> dict[str, Any]:
        fitted = sum(1 for b in self._baselines.values() if b.is_fitted)
        total_obs = sum(b.observation_count for b in self._baselines.values())
        return {
            "total_devices": len(self._baselines),
            "fitted_devices": fitted,
            "total_observations": total_obs,
        }

    def save(self) -> None:
        """Persist all baseline histories to disk."""
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            for device_id, baseline in self._baselines.items():
                path = self._data_dir / _safe_filename(device_id)
                path.write_text(json.dumps(baseline.to_dict(), indent=2))
            logger.debug(
                "DeviceBaselineManager: saved %d baselines to %s",
                len(self._baselines), self._data_dir,
            )
        except OSError as exc:
            logger.warning("DeviceBaselineManager: could not save baselines: %s", exc)

    # -- Internal -------------------------------------------------------

    def _load(self) -> None:
        """Load persisted baselines from disk (non-fatal on any error)."""
        if not self._data_dir.exists():
            return
        loaded = 0
        for path in self._data_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                baseline = DeviceBaseline.from_dict(data)
                self._baselines[baseline.device_id] = baseline
                loaded += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "DeviceBaselineManager: failed to load %s: %s", path.name, exc
                )
        if loaded:
            logger.info(
                "DeviceBaselineManager: loaded %d persisted baselines from %s",
                loaded, self._data_dir,
            )
