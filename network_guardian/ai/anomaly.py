"""
Anomaly Detection — advanced unsupervised anomaly detectors.

Implements Isolation Forest and One-Class SVM (kernel density) algorithms
as pure-Python, zero-dependency implementations suitable for real-time
network telemetry scoring.
"""

from __future__ import annotations

import logging
import math
import random
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("network_guardian.ai.anomaly")


# ---------------------------------------------------------------------------
# Base detector interface
# ---------------------------------------------------------------------------


@dataclass
class AnomalyScore:
    """Result returned by an anomaly detector."""

    score: float  # 0.0 = normal, 1.0 = highly anomalous
    is_anomaly: bool
    method: str
    details: dict[str, Any] = field(default_factory=dict)


class AnomalyDetector(ABC):
    """Abstract base for anomaly detection algorithms."""

    name: str = "base_detector"

    @abstractmethod
    def fit(self, data: list[list[float]]) -> None:
        """Train the detector on normal (baseline) data."""

    @abstractmethod
    def score(self, sample: list[float]) -> AnomalyScore:
        """Score a single sample. Higher = more anomalous."""

    def score_batch(self, samples: list[list[float]]) -> list[AnomalyScore]:
        return [self.score(s) for s in samples]


# ---------------------------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------------------------


@dataclass
class _IsolationNode:
    """A node in an isolation tree."""

    split_feature: int = -1
    split_value: float = 0.0
    left: _IsolationNode | None = None
    right: _IsolationNode | None = None
    size: int = 0  # number of samples at this node (for external nodes)
    is_leaf: bool = False


def _avg_path_length(n: int) -> float:
    """Expected average path length in a BST of n samples (Eq. 1 from the paper)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    h = math.log(n - 1) + 0.5772156649  # Euler-Mascheroni constant
    return 2.0 * h - (2.0 * (n - 1) / n)


class IsolationForest(AnomalyDetector):
    """Isolation Forest for unsupervised anomaly detection.

    Reference: Liu, Ting & Zhou (2008).  Trees are built by randomly
    selecting a feature and split value, then partitioning.  Anomalies
    are isolated in fewer splits so have shorter average path lengths.
    Features are z-score normalised during fit to handle mixed-scale data.
    """

    name = "isolation_forest"

    def __init__(
        self,
        n_trees: int = 100,
        max_samples: int = 256,
        threshold: float = 0.50,
        seed: int | None = None,
    ) -> None:
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.threshold = threshold
        self._rng = random.Random(seed) if seed is not None else secrets.SystemRandom()
        self._trees: list[_IsolationNode] = []
        self._n_samples = 0
        self._mean: list[float] = []
        self._std: list[float] = []

    # -- Normalisation --------------------------------------------------

    def _fit_normaliser(self, data: list[list[float]]) -> None:
        """Compute per-feature mean and std from training data."""
        n = len(data)
        n_feat = len(data[0])
        self._mean = [sum(row[f] for row in data) / n for f in range(n_feat)]
        self._std = [
            max(math.sqrt(sum((row[f] - self._mean[f]) ** 2 for row in data) / n), 1e-9)
            for f in range(n_feat)
        ]

    def _normalise(self, sample: list[float]) -> list[float]:
        if not self._mean:
            return sample
        return [(x - m) / s for x, m, s in zip(sample, self._mean, self._std)]

    # -- Training -------------------------------------------------------

    def fit(self, data: list[list[float]]) -> None:
        if not data:
            return
        self._fit_normaliser(data)
        norm_data = [self._normalise(row) for row in data]
        self._n_samples = min(len(norm_data), self.max_samples)
        max_depth = math.ceil(math.log2(max(self._n_samples, 2)))
        self._trees = []
        for _ in range(self.n_trees):
            sample = self._rng.sample(norm_data, min(len(norm_data), self._n_samples))
            tree = self._build_tree(sample, depth=0, max_depth=max_depth)
            self._trees.append(tree)
        logger.info(
            "IsolationForest fitted: %d trees, %d samples, max_depth=%d",
            self.n_trees, self._n_samples, max_depth,
        )

    def _build_tree(
        self, data: list[list[float]], depth: int, max_depth: int
    ) -> _IsolationNode:
        n = len(data)
        if n <= 1 or depth >= max_depth:
            return _IsolationNode(is_leaf=True, size=n)

        n_features = len(data[0])
        feat = self._rng.randint(0, n_features - 1)
        col = [row[feat] for row in data]
        lo, hi = min(col), max(col)
        if lo == hi:
            return _IsolationNode(is_leaf=True, size=n)

        split = self._rng.uniform(lo, hi)
        left_data = [row for row in data if row[feat] < split]
        right_data = [row for row in data if row[feat] >= split]

        return _IsolationNode(
            split_feature=feat,
            split_value=split,
            left=self._build_tree(left_data, depth + 1, max_depth),
            right=self._build_tree(right_data, depth + 1, max_depth),
        )

    # -- Scoring --------------------------------------------------------

    def _path_length(self, sample: list[float], node: _IsolationNode, depth: int) -> float:
        if node.is_leaf:
            return depth + _avg_path_length(node.size)
        if sample[node.split_feature] < node.split_value:
            return self._path_length(sample, node.left, depth + 1)  # type: ignore[arg-type]
        return self._path_length(sample, node.right, depth + 1)  # type: ignore[arg-type]

    def score(self, sample: list[float]) -> AnomalyScore:
        if not self._trees:
            return AnomalyScore(score=0.0, is_anomaly=False, method=self.name,
                                details={"error": "model not fitted"})
        norm_sample = self._normalise(sample)
        avg_path = sum(
            self._path_length(norm_sample, tree, 0) for tree in self._trees
        ) / len(self._trees)
        c = _avg_path_length(self._n_samples)
        # anomaly score ∈ [0, 1]; closer to 1 = more anomalous
        anomaly_score = 2.0 ** (-avg_path / c) if c > 0 else 0.0
        return AnomalyScore(
            score=anomaly_score,
            is_anomaly=anomaly_score >= self.threshold,
            method=self.name,
            details={"avg_path_length": avg_path, "c_normaliser": c},
        )


# ---------------------------------------------------------------------------
# One-Class SVM (RBF kernel density estimator)
# ---------------------------------------------------------------------------


class OneClassSVM(AnomalyDetector):
    """Simplified one-class SVM using RBF kernel density estimation.

    For each new sample, we compute the average RBF-kernel similarity to
    the support vectors (training points).  Samples with low similarity
    are flagged as anomalies.  This approximation avoids the full
    quadratic-programming solver while keeping the key intuition.
    """

    name = "one_class_svm"

    def __init__(
        self,
        gamma: float | None = None,
        nu: float = 0.1,
        max_support: int = 500,
        seed: int | None = None,
    ) -> None:
        self.gamma = gamma  # if None, use 1/n_features after normalisation
        self.nu = nu  # expected fraction of anomalies in training data
        self._max_support = max_support
        self._rng = random.Random(seed) if seed is not None else secrets.SystemRandom()

        self._support_vectors: list[list[float]] = []
        self._threshold: float = 0.0
        self._gamma_val: float = 1.0
        self._mean: list[float] = []
        self._std: list[float] = []

    # -- Normalisation --------------------------------------------------

    def _fit_normaliser(self, data: list[list[float]]) -> None:
        n = len(data)
        n_feat = len(data[0])
        self._mean = [sum(row[f] for row in data) / n for f in range(n_feat)]
        self._std = [
            max(math.sqrt(sum((row[f] - self._mean[f]) ** 2 for row in data) / n), 1e-9)
            for f in range(n_feat)
        ]

    def _normalise(self, sample: list[float]) -> list[float]:
        if not self._mean:
            return sample
        return [(x - m) / s for x, m, s in zip(sample, self._mean, self._std)]

    def fit(self, data: list[list[float]]) -> None:
        if not data:
            return
        # Fit normaliser on raw data, then normalise
        self._fit_normaliser(data)
        norm_data = [self._normalise(row) for row in data]

        # Subsample for tractability
        if len(norm_data) > self._max_support:
            self._support_vectors = self._rng.sample(norm_data, self._max_support)
        else:
            self._support_vectors = list(norm_data)

        # After normalisation all features are unit-scale, so 1/n_features is meaningful
        n_features = len(data[0])
        self._gamma_val = self.gamma if self.gamma else 1.0 / max(n_features, 1)

        # Compute kernel density for all training points to set threshold
        scores = [self._kernel_density(pt) for pt in self._support_vectors]
        scores.sort()
        # Set threshold at the nu-quantile (bottom nu fraction are outliers)
        idx = max(0, int(len(scores) * self.nu) - 1)
        self._threshold = scores[idx]
        logger.info(
            "OneClassSVM fitted: %d support vectors, gamma=%.4f, threshold=%.4f",
            len(self._support_vectors), self._gamma_val, self._threshold,
        )

    def _rbf(self, a: list[float], b: list[float]) -> float:
        sq_dist = sum((ai - bi) ** 2 for ai, bi in zip(a, b))
        return math.exp(-self._gamma_val * sq_dist)

    def _kernel_density(self, sample: list[float]) -> float:
        if not self._support_vectors:
            return 0.0
        total = sum(self._rbf(sample, sv) for sv in self._support_vectors)
        return total / len(self._support_vectors)

    def score(self, sample: list[float]) -> AnomalyScore:
        if not self._support_vectors:
            return AnomalyScore(score=0.0, is_anomaly=False, method=self.name,
                                details={"error": "model not fitted"})
        norm_sample = self._normalise(sample)
        density = self._kernel_density(norm_sample)
        # Invert: low density → high anomaly score
        anomaly_score = max(0.0, min(1.0, 1.0 - density))
        is_anomaly = density < self._threshold
        return AnomalyScore(
            score=anomaly_score,
            is_anomaly=is_anomaly,
            method=self.name,
            details={"kernel_density": density, "threshold": self._threshold},
        )


# ---------------------------------------------------------------------------
# Ensemble detector
# ---------------------------------------------------------------------------


class EnsembleDetector(AnomalyDetector):
    """Combines multiple detectors via score averaging."""

    name = "ensemble_detector"

    def __init__(self, detectors: list[AnomalyDetector] | None = None, threshold: float = 0.50) -> None:
        self._detectors: list[AnomalyDetector] = detectors or []
        self.threshold = threshold

    def add_detector(self, detector: AnomalyDetector) -> None:
        self._detectors.append(detector)

    def fit(self, data: list[list[float]]) -> None:
        for det in self._detectors:
            det.fit(data)

    def score(self, sample: list[float]) -> AnomalyScore:
        if not self._detectors:
            return AnomalyScore(score=0.0, is_anomaly=False, method=self.name)
        scores = [det.score(sample) for det in self._detectors]
        avg = sum(s.score for s in scores) / len(scores)
        return AnomalyScore(
            score=avg,
            is_anomaly=avg >= self.threshold,
            method=self.name,
            details={
                "individual_scores": {s.method: s.score for s in scores},
            },
        )
