"""
Predictive Modeling — time-series forecasting for network metrics.

Implements:
- ARIMA-style linear forecasting (auto-regressive moving average)
- Prophet-style decomposition (trend + seasonality + residual)
- Exponential smoothing (Holt-Winters)

All implementations are pure-Python with zero external dependencies.
"""

from __future__ import annotations

import logging
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("network_guardian.ai.forecasting")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ForecastPoint:
    """A single point in a forecast."""

    step: int
    value: float
    lower: float  # confidence interval lower bound
    upper: float  # confidence interval upper bound


@dataclass
class ForecastResult:
    """Complete forecast output."""

    method: str
    points: list[ForecastPoint] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)  # MAE, RMSE, etc.


# ---------------------------------------------------------------------------
# Base forecaster
# ---------------------------------------------------------------------------


class Forecaster(ABC):
    """Abstract base class for time-series forecasters."""

    name: str = "base_forecaster"

    @abstractmethod
    def fit(self, series: list[float]) -> dict[str, Any]:
        """Fit the model to historical data. Returns diagnostics."""

    @abstractmethod
    def predict(self, steps: int, confidence: float = 0.95) -> ForecastResult:
        """Forecast `steps` into the future."""


# ---------------------------------------------------------------------------
# AR(p) model — auto-regressive component
# ---------------------------------------------------------------------------


def _ols_coefficients(y: list[float], X: list[list[float]]) -> list[float]:
    """Solve ordinary least squares via normal equations (X^T X)^-1 X^T y."""
    p = len(X[0])
    n = len(y)

    xtx = _compute_xtx(X, n, p)
    xty = [sum(X[k][i] * y[k] for k in range(n)) for i in range(p)]

    return _gauss_jordan_solve(xtx, xty, p)


def _compute_xtx(X: list[list[float]], n: int, p: int) -> list[list[float]]:
    """Compute X^T X matrix."""
    xtx = [[0.0] * p for _ in range(p)]
    for i in range(p):
        for j in range(p):
            xtx[i][j] = sum(X[k][i] * X[k][j] for k in range(n))
    return xtx


def _gauss_jordan_solve(
    matrix: list[list[float]], rhs: list[float], p: int,
) -> list[float]:
    """Solve a linear system via Gauss-Jordan elimination with partial pivoting."""
    aug = [matrix[i][:] + [rhs[i]] for i in range(p)]
    for col in range(p):
        max_row = max(range(col, p), key=lambda r, col=col: abs(aug[r][col]))
        aug[col], aug[max_row] = aug[max_row], aug[col]
        pivot = aug[col][col]
        if abs(pivot) < 1e-12:
            aug[col][col] = 1e-12
            pivot = 1e-12
        for j in range(col, p + 1):
            aug[col][j] /= pivot
        for row in range(p):
            if row != col:
                factor = aug[row][col]
                for j in range(col, p + 1):
                    aug[row][j] -= factor * aug[col][j]
    return [aug[i][p] for i in range(p)]


_INSUFFICIENT_DATA = "insufficient data"


def _compute_std(values: list[float]) -> float:
    """Compute sample standard deviation of a list of floats."""
    if len(values) < 2:
        return 1.0
    m = sum(values) / len(values)
    var = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(max(var, 1e-12))


class ARIMAForecaster(Forecaster):
    """Auto-Regressive Integrated Moving Average forecaster.

    Implements differencing (I), AR(p), and a simple MA approximation
    via residual averaging.  Pure Python, suitable for short-to-medium
    length metric time series.
    """

    name = "arima"

    def __init__(self, p: int = 3, d: int = 1, q: int = 1) -> None:
        self.p = p  # AR order
        self.d = d  # differencing order
        self.q = q  # MA order
        self._ar_coeffs: list[float] = []
        self._ma_coeff: float = 0.0
        self._intercept: float = 0.0
        self._residuals: list[float] = []
        self._original: list[float] = []
        self._differenced: list[float] = []
        self._residual_std: float = 1.0

    def fit(self, series: list[float]) -> dict[str, Any]:
        if len(series) < self.p + self.d + 2:
            return {"error": _INSUFFICIENT_DATA, "min_required": self.p + self.d + 2}

        self._original = list(series)
        self._differenced = self._apply_differencing(series)
        self._fit_ar_model()
        self._fit_ma_component()

        mae = sum(abs(r) for r in self._residuals) / max(len(self._residuals), 1)
        rmse = math.sqrt(sum(r ** 2 for r in self._residuals) / max(len(self._residuals), 1))

        logger.info("ARIMA(%d,%d,%d) fitted: MAE=%.4f, RMSE=%.4f", self.p, self.d, self.q, mae, rmse)
        return {"mae": mae, "rmse": rmse, "ar_coefficients": self._ar_coeffs}

    def _apply_differencing(self, series: list[float]) -> list[float]:
        diff = list(series)
        for _ in range(self.d):
            diff = [diff[i] - diff[i - 1] for i in range(1, len(diff))]
        return diff

    def _fit_ar_model(self) -> None:
        diff = self._differenced
        y = diff[self.p:]
        X = []
        for i in range(self.p, len(diff)):
            row = [1.0]  # intercept
            for lag in range(1, self.p + 1):
                row.append(diff[i - lag])
            X.append(row)

        coeffs = _ols_coefficients(y, X)
        self._intercept = coeffs[0]
        self._ar_coeffs = coeffs[1:]

        # Compute residuals
        self._residuals = []
        for yi, xi in zip(y, X):
            pred = sum(c * v for c, v in zip(coeffs, xi))
            self._residuals.append(yi - pred)

        self._residual_std = _compute_std(self._residuals)

    def _fit_ma_component(self) -> None:
        if self.q > 0 and self._residuals:
            recent = self._residuals[-self.q:]
            self._ma_coeff = sum(recent) / len(recent)
        else:
            self._ma_coeff = 0.0

    def predict(self, steps: int, confidence: float = 0.95) -> ForecastResult:
        diff = list(self._differenced)
        z = 1.96 if confidence >= 0.95 else 1.645  # simple z-score

        points: list[ForecastPoint] = []
        ma_val = self._ma_coeff

        for step in range(1, steps + 1):
            val = self._intercept
            for lag in range(self.p):
                idx = len(diff) - 1 - lag
                val += self._ar_coeffs[lag] * (diff[idx] if idx >= 0 else 0.0)
            val += ma_val
            ma_val *= 0.5  # decay MA influence

            diff.append(val)
            width = z * self._residual_std * math.sqrt(step)
            points.append(ForecastPoint(step=step, value=val, lower=val - width, upper=val + width))

        # Undo differencing to get actual values
        if self.d > 0:
            base = list(self._original)
            for pt in points:
                next_val = base[-1] + pt.value
                pt.value = next_val
                pt.lower = next_val - (pt.upper - pt.value + pt.lower - pt.value) / 2  # adjust CI
                half_w = abs(pt.upper - pt.value)  # keep width
                pt.lower = next_val - half_w
                pt.upper = next_val + half_w
                base.append(next_val)

        return ForecastResult(method=self.name, points=points,
                              metrics={"residual_std": self._residual_std})


# ---------------------------------------------------------------------------
# Prophet-style decomposition
# ---------------------------------------------------------------------------


class SeasonalDecomposer(Forecaster):
    """Prophet-inspired additive decomposition: trend + seasonality + residual.

    Extracts a linear trend, a repeating seasonal pattern, and uses the
    residual distribution for confidence intervals.
    """

    name = "seasonal_decomposer"

    def __init__(self, period: int = 24) -> None:
        self.period = period  # e.g. 24 for hourly data with daily seasonality
        self._trend_slope: float = 0.0
        self._trend_intercept: float = 0.0
        self._seasonal: list[float] = []
        self._residual_std: float = 1.0
        self._n: int = 0

    def fit(self, series: list[float]) -> dict[str, Any]:
        n = len(series)
        if n < self.period + 2:
            return {"error": _INSUFFICIENT_DATA, "min_required": self.period + 2}
        self._n = n

        # 1. Linear trend via OLS: y = a + b*t
        t_mean = (n - 1) / 2.0
        y_mean = sum(series) / n
        num = sum((t - t_mean) * (y - y_mean) for t, y in enumerate(series))
        den = sum((t - t_mean) ** 2 for t in range(n))
        self._trend_slope = num / den if den != 0 else 0.0
        self._trend_intercept = y_mean - self._trend_slope * t_mean

        # 2. Detrend and extract seasonal component
        detrended = [
            series[i] - (self._trend_intercept + self._trend_slope * i)
            for i in range(n)
        ]
        self._seasonal = [0.0] * self.period
        counts = [0] * self.period
        for i, val in enumerate(detrended):
            idx = i % self.period
            self._seasonal[idx] += val
            counts[idx] += 1
        self._seasonal = [
            s / c if c > 0 else 0.0 for s, c in zip(self._seasonal, counts)
        ]
        # Normalize seasonal to sum to zero
        s_mean = sum(self._seasonal) / self.period
        self._seasonal = [s - s_mean for s in self._seasonal]

        # 3. Residuals
        residuals = [
            series[i] - (self._trend_intercept + self._trend_slope * i + self._seasonal[i % self.period])
            for i in range(n)
        ]
        self._residual_std = _compute_std(residuals)

        mae = sum(abs(r) for r in residuals) / max(len(residuals), 1)
        logger.info("SeasonalDecomposer fitted: period=%d, slope=%.4f, MAE=%.4f",
                     self.period, self._trend_slope, mae)
        return {"mae": mae, "trend_slope": self._trend_slope, "seasonal_amplitude": max(self._seasonal) - min(self._seasonal)}

    def predict(self, steps: int, confidence: float = 0.95) -> ForecastResult:
        z = 1.96 if confidence >= 0.95 else 1.645
        points: list[ForecastPoint] = []
        for step in range(1, steps + 1):
            t = self._n + step - 1
            trend = self._trend_intercept + self._trend_slope * t
            seasonal = self._seasonal[t % self.period] if self._seasonal else 0.0
            value = trend + seasonal
            width = z * self._residual_std * math.sqrt(step)
            points.append(ForecastPoint(step=step, value=value,
                                        lower=value - width, upper=value + width))
        return ForecastResult(method=self.name, points=points,
                              metrics={"residual_std": self._residual_std})


# ---------------------------------------------------------------------------
# Exponential Smoothing (Holt-Winters additive)
# ---------------------------------------------------------------------------


class HoltWintersForecaster(Forecaster):
    """Holt-Winters (triple) exponential smoothing with additive seasonality."""

    name = "holt_winters"

    def __init__(
        self,
        period: int = 24,
        alpha: float = 0.3,
        beta: float = 0.1,
        gamma: float = 0.1,
    ) -> None:
        self.period = period
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self._level: float = 0.0
        self._trend: float = 0.0
        self._seasonal: list[float] = []
        self._residual_std: float = 1.0
        self._n: int = 0

    def fit(self, series: list[float]) -> dict[str, Any]:
        n = len(series)
        if n < 2 * self.period:
            return {"error": _INSUFFICIENT_DATA, "min_required": 2 * self.period}
        self._n = n

        # Initialise level and trend from first two periods
        first_period = series[: self.period]
        second_period = series[self.period : 2 * self.period]
        self._level = sum(first_period) / self.period
        self._trend = (sum(second_period) - sum(first_period)) / (self.period ** 2)

        # Initialise seasonal indices
        self._seasonal = [series[i] - self._level for i in range(self.period)]

        # Fit
        residuals: list[float] = []
        for i in range(self.period, n):
            si = i % self.period
            y = series[i]
            predicted = self._level + self._trend + self._seasonal[si]
            residuals.append(y - predicted)

            new_level = self.alpha * (y - self._seasonal[si]) + (1 - self.alpha) * (self._level + self._trend)
            new_trend = self.beta * (new_level - self._level) + (1 - self.beta) * self._trend
            self._seasonal[si] = self.gamma * (y - new_level) + (1 - self.gamma) * self._seasonal[si]
            self._level = new_level
            self._trend = new_trend

        if len(residuals) >= 2:
            r_mean = sum(residuals) / len(residuals)
            var = sum((r - r_mean) ** 2 for r in residuals) / (len(residuals) - 1)
            self._residual_std = math.sqrt(max(var, 1e-12))

        mae = sum(abs(r) for r in residuals) / max(len(residuals), 1)
        logger.info("HoltWinters fitted: period=%d, MAE=%.4f", self.period, mae)
        return {"mae": mae, "final_level": self._level, "final_trend": self._trend}

    def predict(self, steps: int, confidence: float = 0.95) -> ForecastResult:
        z = 1.96 if confidence >= 0.95 else 1.645
        points: list[ForecastPoint] = []
        for step in range(1, steps + 1):
            si = (self._n + step - 1) % self.period
            value = self._level + self._trend * step + (self._seasonal[si] if self._seasonal else 0.0)
            width = z * self._residual_std * math.sqrt(step)
            points.append(ForecastPoint(step=step, value=value,
                                        lower=value - width, upper=value + width))
        return ForecastResult(method=self.name, points=points,
                              metrics={"residual_std": self._residual_std})
