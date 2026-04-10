"""
ML Training Pipeline — end-to-end training orchestration.

Provides:
- **TrainingPipeline**: trains anomaly detectors and forecasters on datasets
- **ModelRegistry**: versioned storage of trained model states
- **TrainingReport**: structured output with metrics (accuracy, F1, MAE, …)

The pipeline integrates with the Dataset / DataPoint structures from
``ai.datasets`` and the model classes from ``ai.anomaly`` / ``ai.forecasting``.
"""

from __future__ import annotations

import logging
import math
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from network_guardian.ai.datasets import DataLabel, Dataset, normalise_features

if TYPE_CHECKING:
    from network_guardian.ai.anomaly import AnomalyDetector, AnomalyScore
    from network_guardian.ai.forecasting import Forecaster, ForecastResult

logger = logging.getLogger("network_guardian.ai.training")


# ---------------------------------------------------------------------------
# Training report
# ---------------------------------------------------------------------------


@dataclass
class TrainingReport:
    """Structured result of a training run."""

    model_name: str
    dataset_name: str
    train_samples: int
    test_samples: int
    duration_secs: float
    metrics: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def accuracy(self) -> float | None:
        return self.metrics.get("accuracy")

    @property
    def f1_score(self) -> float | None:
        return self.metrics.get("f1")

    def summary(self) -> str:
        lines = [
            f"=== Training Report: {self.model_name} ===",
            f"Dataset     : {self.dataset_name}",
            f"Train/Test  : {self.train_samples}/{self.test_samples}",
            f"Duration    : {self.duration_secs:.2f}s",
        ]
        for k, v in self.metrics.items():
            lines.append(f"  {k:16s}: {v:.4f}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Model snapshot registry
# ---------------------------------------------------------------------------


@dataclass
class ModelSnapshot:
    """Lightweight snapshot of a trained model state."""

    name: str
    version: int
    trained_at: datetime
    report: TrainingReport
    params: dict[str, Any] = field(default_factory=dict)


class ModelRegistry:
    """Versioned registry of trained model snapshots."""

    def __init__(self) -> None:
        self._snapshots: dict[str, list[ModelSnapshot]] = {}

    def register(self, snapshot: ModelSnapshot) -> None:
        self._snapshots.setdefault(snapshot.name, []).append(snapshot)
        logger.info("Model snapshot registered: %s v%d", snapshot.name, snapshot.version)

    def latest(self, name: str) -> ModelSnapshot | None:
        versions = self._snapshots.get(name, [])
        return versions[-1] if versions else None

    def all_versions(self, name: str) -> list[ModelSnapshot]:
        return list(self._snapshots.get(name, []))

    @property
    def model_names(self) -> list[str]:
        return list(self._snapshots.keys())


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------


class TrainingPipeline:
    """End-to-end ML training orchestrator.

    Workflow:
    1.  Accept a ``Dataset`` (from generators or CSV loader)
    2.  Split into train / test
    3.  Optionally normalise features
    4.  Fit the detector / forecaster on training data
    5.  Evaluate on test data
    6.  Produce a ``TrainingReport`` and register a ``ModelSnapshot``
    """

    def __init__(self, registry: ModelRegistry | None = None) -> None:
        self.registry = registry or ModelRegistry()

    # -- Anomaly detector training ---------------------------------------

    def train_anomaly_detector(
        self,
        detector: AnomalyDetector,
        dataset: Dataset,
        *,
        normalise: bool = True,
        train_ratio: float = 0.8,
        seed: int = 42,
    ) -> TrainingReport:
        """Train an anomaly detector and evaluate on held-out data."""
        t0 = time.monotonic()

        if normalise:
            dataset = normalise_features(dataset)

        train_ds, test_ds = dataset.split(train_ratio=train_ratio, seed=seed)

        # Train on *normal* samples only (unsupervised)
        normal_train = [dp.features for dp in train_ds.points
                        if dp.label in (DataLabel.NORMAL, DataLabel.UNKNOWN)]
        if not normal_train:
            normal_train = train_ds.feature_matrix()  # fallback
        detector.fit(normal_train)

        # Evaluate
        tp = fp = tn = fn = 0
        for dp in test_ds.points:
            result = detector.score(dp.features)
            actual_anomaly = dp.label not in (DataLabel.NORMAL, DataLabel.UNKNOWN)
            if result.is_anomaly and actual_anomaly:
                tp += 1
            elif result.is_anomaly and not actual_anomaly:
                fp += 1
            elif not result.is_anomaly and actual_anomaly:
                fn += 1
            else:
                tn += 1

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
               if (precision + recall) else 0.0)

        duration = time.monotonic() - t0
        report = TrainingReport(
            model_name=detector.name,
            dataset_name=dataset.name,
            train_samples=len(train_ds),
            test_samples=len(test_ds),
            duration_secs=round(duration, 3),
            metrics={
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
        )

        # Register snapshot
        versions = self.registry.all_versions(detector.name)
        snapshot = ModelSnapshot(
            name=detector.name,
            version=len(versions) + 1,
            trained_at=datetime.now(timezone.utc),
            report=report,
        )
        self.registry.register(snapshot)

        logger.info("Anomaly detector trained: %s — accuracy=%.2f%%, f1=%.4f",
                     detector.name, accuracy * 100, f1)
        return report

    # -- Forecaster training ---------------------------------------------

    def train_forecaster(
        self,
        forecaster: Forecaster,
        series: list[float],
        *,
        holdout: int = 10,
    ) -> TrainingReport:
        """Train a forecaster and evaluate on held-out tail of the series."""
        t0 = time.monotonic()

        if len(series) <= holdout + 5:
            return TrainingReport(
                model_name=forecaster.name,
                dataset_name="timeseries",
                train_samples=len(series),
                test_samples=0,
                duration_secs=0.0,
                metrics={"error": 1.0},
                metadata={"reason": "insufficient data"},
            )

        train_series = series[:-holdout]
        actual_tail = series[-holdout:]

        fit_diag = forecaster.fit(train_series)
        result = forecaster.predict(holdout)

        # Compute MAE and RMSE against actual tail
        predicted = [pt.value for pt in result.points]
        errors = [abs(a - p) for a, p in zip(actual_tail, predicted)]
        sq_errors = [(a - p) ** 2 for a, p in zip(actual_tail, predicted)]
        mae = sum(errors) / len(errors) if errors else 0.0
        rmse = math.sqrt(sum(sq_errors) / len(sq_errors)) if sq_errors else 0.0

        # Coverage: what fraction of actuals fall within confidence intervals?
        coverage = sum(
            1 for a, pt in zip(actual_tail, result.points)
            if pt.lower <= a <= pt.upper
        ) / len(actual_tail) if actual_tail else 0.0

        duration = time.monotonic() - t0
        report = TrainingReport(
            model_name=forecaster.name,
            dataset_name="timeseries",
            train_samples=len(train_series),
            test_samples=holdout,
            duration_secs=round(duration, 3),
            metrics={
                "mae": round(mae, 4),
                "rmse": round(rmse, 4),
                "coverage": round(coverage, 4),
            },
            metadata=fit_diag,
        )

        versions = self.registry.all_versions(forecaster.name)
        snapshot = ModelSnapshot(
            name=forecaster.name,
            version=len(versions) + 1,
            trained_at=datetime.now(timezone.utc),
            report=report,
        )
        self.registry.register(snapshot)

        logger.info("Forecaster trained: %s — MAE=%.4f, RMSE=%.4f, coverage=%.0f%%",
                     forecaster.name, mae, rmse, coverage * 100)
        return report

    # -- Full pipeline: generate + train in one call ---------------------

    def run_full_anomaly_pipeline(
        self,
        n_normal: int = 800,
        n_anomaly: int = 50,
        n_attack: int = 50,
        n_scan: int = 50,
        seed: int = 42,
    ) -> TrainingReport:
        """Generate synthetic data, build an ensemble, train & evaluate."""
        from network_guardian.ai.anomaly import EnsembleDetector, IsolationForest, OneClassSVM
        from network_guardian.ai.datasets import NetworkTrafficGenerator

        gen = NetworkTrafficGenerator(seed=seed)
        dataset = gen.generate(n_normal=n_normal, n_anomaly=n_anomaly,
                               n_attack=n_attack, n_scan=n_scan)

        ensemble = EnsembleDetector()
        ensemble.add_detector(IsolationForest(n_trees=80, max_samples=256, seed=seed))
        ensemble.add_detector(OneClassSVM(nu=0.15, seed=seed))

        return self.train_anomaly_detector(ensemble, dataset, seed=seed)

    def run_full_forecast_pipeline(
        self,
        length: int = 720,
        period: int = 24,
        method: str = "arima",
        holdout: int = 24,
        seed: int = 42,
    ) -> TrainingReport:
        """Generate synthetic time-series, train a forecaster & evaluate."""
        from network_guardian.ai.datasets import MetricTimeSeriesGenerator
        from network_guardian.ai.forecasting import (
            ARIMAForecaster, HoltWintersForecaster, SeasonalDecomposer,
        )

        gen = MetricTimeSeriesGenerator(seed=seed)
        _, series = gen.generate(length=length, period=period)

        if method == "arima":
            forecaster = ARIMAForecaster(p=3, d=1, q=1)
        elif method == "seasonal":
            forecaster = SeasonalDecomposer(period=period)
        elif method == "holt_winters":
            forecaster = HoltWintersForecaster(period=period)
        else:
            raise ValueError(f"Unknown method: {method}")

        return self.train_forecaster(forecaster, series, holdout=holdout)
