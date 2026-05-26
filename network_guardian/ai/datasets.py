# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Dataset Loaders & Synthetic Generators — data sources for ML training.

Provides:
- Synthetic network traffic / metric generators for bootstrapping
- CSV-based dataset loader for external datasets (UCI, Kaggle, custom)
- Feature extraction pipeline that converts raw data to model-ready vectors

All generators are deterministic when seeded, enabling reproducible training.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import math
import os
import random
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("network_guardian.ai.datasets")


# ---------------------------------------------------------------------------
# Data point
# ---------------------------------------------------------------------------


class DataLabel(Enum):
    NORMAL = "normal"
    ANOMALY = "anomaly"
    ATTACK = "attack"
    SCAN = "scan"
    UNKNOWN = "unknown"


@dataclass
class DataPoint:
    """A single training / evaluation sample."""

    features: list[float]
    label: DataLabel = DataLabel.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Dataset:
    """A collection of DataPoints with metadata."""

    name: str
    points: list[DataPoint] = field(default_factory=list)
    feature_names: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.points)

    def feature_matrix(self) -> list[list[float]]:
        return [dp.features for dp in self.points]

    def labels(self) -> list[str]:
        return [dp.label.value for dp in self.points]

    def split(
        self, train_ratio: float = 0.8, seed: int = 42
    ) -> tuple[Dataset, Dataset]:
        """Split into train / test datasets."""
        rng = random.Random(seed)
        indices = list(range(len(self.points)))
        rng.shuffle(indices)
        split_idx = int(len(indices) * train_ratio)
        train_pts = [self.points[i] for i in indices[:split_idx]]
        test_pts = [self.points[i] for i in indices[split_idx:]]
        return (
            Dataset(name=f"{self.name}_train", points=train_pts,
                    feature_names=self.feature_names, metadata=self.metadata),
            Dataset(name=f"{self.name}_test", points=test_pts,
                    feature_names=self.feature_names, metadata=self.metadata),
        )


# ---------------------------------------------------------------------------
# Synthetic generators
# ---------------------------------------------------------------------------


class NetworkTrafficGenerator:
    """Generate synthetic network traffic data for anomaly detection training.

    Produces feature vectors mimicking real network flow records:
    [bytes_sent, bytes_recv, packets, duration_ms, port, protocol_flag,
     connection_rate, error_rate]
    """

    FEATURE_NAMES = [
        "bytes_sent", "bytes_recv", "packets", "duration_ms",
        "dst_port", "protocol_flag", "conn_rate", "error_rate",
    ]

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)

    def generate(
        self,
        n_normal: int = 800,
        n_anomaly: int = 50,
        n_attack: int = 50,
        n_scan: int = 50,
    ) -> Dataset:
        points: list[DataPoint] = []
        for _ in range(n_normal):
            points.append(self._normal_flow())
        for _ in range(n_anomaly):
            points.append(self._anomalous_flow())
        for _ in range(n_attack):
            points.append(self._attack_flow())
        for _ in range(n_scan):
            points.append(self._scan_flow())

        self._rng.shuffle(points)
        return Dataset(
            name="synthetic_network_traffic",
            points=points,
            feature_names=self.FEATURE_NAMES,
            metadata={"n_normal": n_normal, "n_anomaly": n_anomaly,
                       "n_attack": n_attack, "n_scan": n_scan},
        )

    def _normal_flow(self) -> DataPoint:
        return DataPoint(
            features=[
                self._rng.gauss(5000, 2000),      # bytes_sent
                self._rng.gauss(8000, 3000),       # bytes_recv
                self._rng.gauss(50, 15),           # packets
                self._rng.gauss(200, 80),          # duration_ms
                self._rng.choice([80, 443, 8080, 8443, 53]),  # dst_port
                self._rng.choice([0, 1]),          # protocol (0=TCP, 1=UDP)
                self._rng.gauss(10, 3),            # conn_rate (per sec)
                self._rng.gauss(0.01, 0.005),      # error_rate
            ],
            label=DataLabel.NORMAL,
        )

    def _anomalous_flow(self) -> DataPoint:
        return DataPoint(
            features=[
                self._rng.gauss(50000, 20000),     # unusually large
                self._rng.gauss(500, 200),         # asymmetric
                self._rng.gauss(500, 100),         # high packet count
                self._rng.gauss(5000, 2000),       # long duration
                self._rng.choice([445, 3389, 6379, 27017]),
                self._rng.choice([0, 1]),
                self._rng.gauss(100, 30),          # high conn rate
                self._rng.gauss(0.15, 0.05),       # elevated errors
            ],
            label=DataLabel.ANOMALY,
        )

    def _attack_flow(self) -> DataPoint:
        return DataPoint(
            features=[
                self._rng.gauss(100000, 30000),    # data exfil volume
                self._rng.gauss(200, 80),          # minimal response
                self._rng.gauss(1000, 200),        # burst packets
                self._rng.gauss(100, 40),          # short burst
                self._rng.choice([4444, 5555, 1337, 31337]),  # C2 ports
                0,                                  # TCP
                self._rng.gauss(500, 100),         # very high rate
                self._rng.gauss(0.3, 0.1),         # high errors
            ],
            label=DataLabel.ATTACK,
        )

    def _scan_flow(self) -> DataPoint:
        return DataPoint(
            features=[
                self._rng.gauss(100, 30),          # tiny payloads
                self._rng.gauss(60, 20),
                self._rng.gauss(3, 1),             # few packets per conn
                self._rng.gauss(20, 10),           # very short
                self._rng.randint(1, 65535),       # random ports
                0,                                  # TCP SYN scanning
                self._rng.gauss(200, 50),          # high rate
                self._rng.gauss(0.5, 0.15),        # mostly RST/timeout
            ],
            label=DataLabel.SCAN,
        )


class MetricTimeSeriesGenerator:
    """Generate synthetic time-series data (CPU, latency, bandwidth).

    Produces series with trend, seasonality, and optional anomaly spikes —
    suitable for training forecasting and anomaly detection models.
    """

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)

    def generate(
        self,
        length: int = 720,
        period: int = 24,
        trend: float = 0.02,
        noise_std: float = 1.0,
        anomaly_fraction: float = 0.03,
        metric_name: str = "cpu_usage",
    ) -> tuple[Dataset, list[float]]:
        """Return a Dataset of single-feature points AND the raw series.

        The raw series list is useful for direct forecaster training.
        """
        series: list[float] = []
        points: list[DataPoint] = []
        n_anomalies = int(length * anomaly_fraction)
        anomaly_positions = set(self._rng.sample(range(length), min(n_anomalies, length)))

        for i in range(length):
            base = 50 + trend * i
            seasonal = 15 * math.sin(2 * math.pi * i / period)
            noise = self._rng.gauss(0, noise_std)
            value = base + seasonal + noise

            if i in anomaly_positions:
                spike = self._rng.uniform(30, 60) * self._rng.choice([1, -1])
                value += spike
                label = DataLabel.ANOMALY
            else:
                label = DataLabel.NORMAL

            series.append(value)
            points.append(DataPoint(
                features=[value],
                label=label,
                metadata={"time_index": i, "metric_name": metric_name},
            ))

        dataset = Dataset(
            name=f"synthetic_{metric_name}",
            points=points,
            feature_names=[metric_name],
            metadata={"length": length, "period": period, "trend": trend},
        )
        return dataset, series


# ---------------------------------------------------------------------------
# CSV / file loader
# ---------------------------------------------------------------------------


class CSVDatasetLoader:
    """Load tabular data from CSV files or strings.

    Supports external datasets (UCI ML Repository, Kaggle exports, etc.).
    The loader auto-detects numeric columns and converts them to features.
    A ``label_column`` can be specified to separate labels from features.
    """

    def __init__(
        self,
        label_column: str | None = None,
        label_map: dict[str, DataLabel] | None = None,
    ) -> None:
        self._label_column = label_column
        self._label_map = label_map or {}

    def load_file(self, path: str | Path) -> Dataset:
        """Load from a file path."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Dataset not found: {p}")
        text = p.read_text(encoding="utf-8")
        return self._parse(text, name=p.stem)

    def load_string(self, csv_text: str, name: str = "csv_dataset") -> Dataset:
        """Load from an in-memory CSV string."""
        return self._parse(csv_text, name=name)

    def _parse(self, text: str, name: str) -> Dataset:
        reader = csv.DictReader(io.StringIO(text))
        feature_names: list[str] = []
        points: list[DataPoint] = []

        for row in reader:
            if not feature_names:
                feature_names = [k for k in row if k != self._label_column]

            features: list[float] = []
            for col in feature_names:
                try:
                    features.append(float(row[col]))
                except (ValueError, TypeError):
                    features.append(0.0)

            label = DataLabel.UNKNOWN
            if self._label_column and self._label_column in row:
                raw = row[self._label_column].strip().lower()
                label = self._label_map.get(raw, DataLabel.UNKNOWN)

            points.append(DataPoint(features=features, label=label,
                                    metadata=dict(row)))

        return Dataset(name=name, points=points, feature_names=feature_names)


# ---------------------------------------------------------------------------
# Feature extraction utilities
# ---------------------------------------------------------------------------


def normalise_features(dataset: Dataset) -> Dataset:
    """Min-max normalise each feature column to [0, 1]."""
    if not dataset.points:
        return dataset

    n_features = len(dataset.points[0].features)
    mins = [float("inf")] * n_features
    maxs = [float("-inf")] * n_features

    for dp in dataset.points:
        for i, v in enumerate(dp.features):
            mins[i] = min(mins[i], v)
            maxs[i] = max(maxs[i], v)

    new_points: list[DataPoint] = []
    for dp in dataset.points:
        normed = []
        for i, v in enumerate(dp.features):
            span = maxs[i] - mins[i]
            normed.append((v - mins[i]) / span if span > 0 else 0.0)
        new_points.append(DataPoint(features=normed, label=dp.label,
                                    metadata=dp.metadata))

    return Dataset(name=dataset.name + "_normalised", points=new_points,
                   feature_names=dataset.feature_names,
                   metadata={**dataset.metadata, "normalised": True,
                             "min_values": mins, "max_values": maxs})


def compute_statistics(dataset: Dataset) -> dict[str, dict[str, float]]:
    """Compute per-feature mean, std, min, max."""
    if not dataset.points:
        return {}
    n = len(dataset.points[0].features)
    names = dataset.feature_names or [f"feature_{i}" for i in range(n)]
    stats: dict[str, dict[str, float]] = {}
    for i, name in enumerate(names):
        col = [dp.features[i] for dp in dataset.points]
        mean = sum(col) / len(col)
        var = sum((v - mean) ** 2 for v in col) / max(len(col) - 1, 1)
        stats[name] = {
            "mean": mean,
            "std": math.sqrt(var),
            "min": min(col),
            "max": max(col),
        }
    return stats
