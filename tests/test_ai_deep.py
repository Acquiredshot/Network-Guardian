"""Comprehensive tests for deep AI modules — anomaly detection, forecasting,
audit analysis, smart automation, and AIEngine integration."""

from __future__ import annotations

import math
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone

from network_guardian.ai.anomaly import (
    AnomalyScore,
    EnsembleDetector,
    IsolationForest,
    OneClassSVM,
)
from network_guardian.ai.forecasting import (
    ARIMAForecaster,
    ForecastResult,
    HoltWintersForecaster,
    SeasonalDecomposer,
)
from network_guardian.ai.audit_analyzer import HostRiskProfile, NetworkAuditAnalyzer
from network_guardian.ai.smart_automation import SmartAutomation, TaskRecommendation
from network_guardian.automator import TaskResult, TaskStatus
from network_guardian.config import Config
from network_guardian.core.events import EventBus
from network_guardian.models.network import Finding, Host, HostStatus, Severity


# ===================================================================
# Anomaly Detection
# ===================================================================


class TestIsolationForest:
    """Tests for the Isolation Forest detector."""

    def _make_normal_data(self, n: int = 200) -> list[list[float]]:
        """Simple cluster centred at (5, 5)."""
        import random
        rng = random.Random(42)
        return [[5 + rng.gauss(0, 0.5), 5 + rng.gauss(0, 0.5)] for _ in range(n)]

    def test_fit_and_score_normal(self):
        iforest = IsolationForest(n_trees=50, max_samples=128, seed=42)
        data = self._make_normal_data()
        iforest.fit(data)
        result = iforest.score([5.0, 5.0])
        assert isinstance(result, AnomalyScore)
        assert 0.0 <= result.score <= 1.0
        assert result.method == "isolation_forest"

    def test_anomaly_scores_higher_for_outliers(self):
        iforest = IsolationForest(n_trees=80, max_samples=128, threshold=0.6, seed=42)
        data = self._make_normal_data()
        iforest.fit(data)
        normal = iforest.score([5.0, 5.0])
        outlier = iforest.score([50.0, 50.0])
        assert outlier.score > normal.score

    def test_flag_severe_outlier(self):
        iforest = IsolationForest(n_trees=80, max_samples=128, threshold=0.6, seed=42)
        data = self._make_normal_data()
        iforest.fit(data)
        outlier = iforest.score([100.0, 100.0])
        assert outlier.is_anomaly is True

    def test_unfitted_returns_zero(self):
        iforest = IsolationForest()
        result = iforest.score([1.0, 2.0])
        assert result.score == 0.0
        assert result.is_anomaly is False

    def test_score_batch(self):
        iforest = IsolationForest(n_trees=30, seed=42)
        data = self._make_normal_data(100)
        iforest.fit(data)
        results = iforest.score_batch([[5.0, 5.0], [50.0, 50.0]])
        assert len(results) == 2


class TestOneClassSVM:
    """Tests for the One-Class SVM detector."""

    def _make_data(self, n: int = 100) -> list[list[float]]:
        import random
        rng = random.Random(99)
        return [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(n)]

    def test_fit_and_score(self):
        svm = OneClassSVM(nu=0.1, seed=99)
        data = self._make_data()
        svm.fit(data)
        result = svm.score([0.0, 0.0])
        assert isinstance(result, AnomalyScore)
        assert result.method == "one_class_svm"
        assert 0.0 <= result.score <= 1.0

    def test_outlier_higher_score(self):
        svm = OneClassSVM(nu=0.1, seed=99)
        data = self._make_data()
        svm.fit(data)
        normal = svm.score([0.0, 0.0])
        outlier = svm.score([20.0, 20.0])
        assert outlier.score > normal.score

    def test_unfitted_returns_zero(self):
        svm = OneClassSVM()
        result = svm.score([1.0, 2.0])
        assert result.score == 0.0


class TestEnsembleDetector:
    """Tests for the ensemble combining multiple detectors."""

    def test_ensemble_averages_scores(self):
        import random
        rng = random.Random(42)
        data = [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(100)]
        ensemble = EnsembleDetector()
        ensemble.add_detector(IsolationForest(n_trees=30, seed=42))
        ensemble.add_detector(OneClassSVM(nu=0.1, seed=42))
        ensemble.fit(data)
        result = ensemble.score([0.0, 0.0])
        assert result.method == "ensemble_detector"
        assert "individual_scores" in result.details

    def test_empty_ensemble(self):
        ensemble = EnsembleDetector()
        result = ensemble.score([1.0])
        assert result.score == 0.0


# ===================================================================
# Forecasting
# ===================================================================


class TestARIMAForecaster:
    """Tests for the ARIMA forecaster."""

    def _trending_series(self, n: int = 100) -> list[float]:
        """Linear trend with noise."""
        import random
        rng = random.Random(7)
        return [2.0 * i + rng.gauss(0, 1) for i in range(n)]

    def test_fit_returns_metrics(self):
        f = ARIMAForecaster(p=3, d=1, q=1)
        diag = f.fit(self._trending_series())
        assert "mae" in diag
        assert "rmse" in diag
        assert diag["mae"] >= 0

    def test_predict_returns_points(self):
        f = ARIMAForecaster(p=3, d=1, q=1)
        f.fit(self._trending_series())
        result = f.predict(5)
        assert isinstance(result, ForecastResult)
        assert len(result.points) == 5
        assert result.method == "arima"

    def test_confidence_intervals(self):
        f = ARIMAForecaster(p=3, d=1, q=1)
        f.fit(self._trending_series())
        result = f.predict(5)
        for pt in result.points:
            assert pt.lower <= pt.value <= pt.upper

    def test_insufficient_data(self):
        f = ARIMAForecaster(p=3, d=1, q=1)
        diag = f.fit([1.0, 2.0])
        assert "error" in diag


class TestSeasonalDecomposer:
    """Tests for Prophet-style seasonal decomposition."""

    def _seasonal_series(self, n: int = 120, period: int = 12) -> list[float]:
        import random, math
        rng = random.Random(3)
        return [
            10 + 0.1 * i + 5 * math.sin(2 * math.pi * i / period) + rng.gauss(0, 0.5)
            for i in range(n)
        ]

    def test_fit_and_predict(self):
        sd = SeasonalDecomposer(period=12)
        diag = sd.fit(self._seasonal_series())
        assert "mae" in diag
        result = sd.predict(12)
        assert len(result.points) == 12
        assert result.method == "seasonal_decomposer"

    def test_detects_positive_trend(self):
        sd = SeasonalDecomposer(period=12)
        diag = sd.fit(self._seasonal_series())
        assert diag["trend_slope"] > 0  # data has positive trend

    def test_insufficient_data(self):
        sd = SeasonalDecomposer(period=24)
        diag = sd.fit([1.0] * 10)
        assert "error" in diag


class TestHoltWinters:
    """Tests for Holt-Winters exponential smoothing."""

    def _series(self, n: int = 96, period: int = 12) -> list[float]:
        import random, math
        rng = random.Random(5)
        return [
            50 + 0.2 * i + 10 * math.sin(2 * math.pi * i / period) + rng.gauss(0, 1)
            for i in range(n)
        ]

    def test_fit_and_predict(self):
        hw = HoltWintersForecaster(period=12)
        diag = hw.fit(self._series())
        assert "mae" in diag
        result = hw.predict(12)
        assert len(result.points) == 12
        assert result.method == "holt_winters"

    def test_insufficient_data(self):
        hw = HoltWintersForecaster(period=24)
        diag = hw.fit([1.0] * 10)
        assert "error" in diag


# ===================================================================
# Audit Analyzer
# ===================================================================


class TestNetworkAuditAnalyzer:
    """Tests for ML-powered network audit analysis."""

    def _make_hosts(self, n: int = 10) -> list[Host]:
        hosts = []
        for i in range(n):
            hosts.append(Host(
                ip=f"10.0.0.{i + 1}",
                status=HostStatus.UP,
                open_ports=[22, 80, 443] if i < n - 1 else [21, 23, 445, 3389, 5900],
            ))
        return hosts

    def test_analyse_fleet(self):
        analyzer = NetworkAuditAnalyzer()
        hosts = self._make_hosts(10)
        profiles = analyzer.analyse(hosts)
        assert len(profiles) == 10
        assert all(isinstance(p, HostRiskProfile) for p in profiles)

    def test_risky_host_scores_high(self):
        analyzer = NetworkAuditAnalyzer()
        risky = Host(ip="10.0.0.99", status=HostStatus.UP,
                     open_ports=[21, 23, 445, 3389, 5900, 6379, 27017])
        profile = analyzer.score_single(risky)
        assert profile.risk_score > 0.5
        assert len(profile.high_risk_services) > 0
        assert len(profile.findings) > 0

    def test_safe_host_scores_low(self):
        analyzer = NetworkAuditAnalyzer()
        safe = Host(ip="10.0.0.1", status=HostStatus.UP, open_ports=[443])
        profile = analyzer.score_single(safe)
        assert profile.risk_score < 0.3

    def test_down_host(self):
        analyzer = NetworkAuditAnalyzer()
        down = Host(ip="10.0.0.1", status=HostStatus.DOWN, open_ports=[])
        profile = analyzer.score_single(down)
        assert profile.risk_score == 0.0

    def test_excessive_ports_finding(self):
        analyzer = NetworkAuditAnalyzer()
        host = Host(ip="10.0.0.1", status=HostStatus.UP,
                    open_ports=list(range(1, 30)))
        profile = analyzer.score_single(host)
        titles = [f.title for f in profile.findings]
        assert any("Excessive open ports" in t for t in titles)

    def test_fleet_anomaly_detection(self):
        """A host wildly different from the fleet should be flagged."""
        analyzer = NetworkAuditAnalyzer()
        # 9 quiet hosts + 1 very exposed host
        hosts = self._make_hosts(10)
        profiles = analyzer.analyse(hosts)
        # The last host (very exposed) should have an anomaly score
        exposed = [p for p in profiles if p.host_ip == "10.0.0.10"][0]
        assert exposed.anomaly_score > 0.0 or exposed.risk_score > 0.5


# ===================================================================
# Smart Automation
# ===================================================================


class TestSmartAutomation:
    """Tests for ML-driven task recommendation."""

    def _make_history(self) -> list[TaskResult]:
        now = datetime.now(timezone.utc)
        return [
            TaskResult(
                task_name="firewall_audit",
                status=TaskStatus.COMPLETED,
                started_at=now - timedelta(hours=10),
                finished_at=now - timedelta(hours=9, minutes=50),
            ),
            TaskResult(
                task_name="firewall_audit",
                status=TaskStatus.COMPLETED,
                started_at=now - timedelta(hours=5),
                finished_at=now - timedelta(hours=4, minutes=55),
            ),
            TaskResult(
                task_name="patch_smb",
                status=TaskStatus.FAILED,
                error="timeout",
                started_at=now - timedelta(hours=3),
                finished_at=now - timedelta(hours=2, minutes=50),
            ),
            TaskResult(
                task_name="patch_smb",
                status=TaskStatus.FAILED,
                error="timeout",
                started_at=now - timedelta(hours=1),
                finished_at=now - timedelta(minutes=50),
            ),
        ]

    def test_learn_from_history(self):
        sa = SmartAutomation()
        profiles = sa.learn_from_history(self._make_history())
        assert "firewall_audit" in profiles
        assert profiles["firewall_audit"].successes == 2
        assert profiles["patch_smb"].failures == 2

    def test_recommend_tasks_from_findings(self):
        sa = SmartAutomation()
        findings = [
            Finding(title="SMB: EternalBlue vector", description="Port 445 open",
                    severity=Severity.HIGH, host="10.0.0.1"),
            Finding(title="Cleartext FTP", description="FTP cleartext credentials",
                    severity=Severity.MEDIUM, host="10.0.0.2"),
        ]
        recs = sa.recommend_tasks(findings, available_tasks=["patch_smb", "enforce_encryption"])
        assert len(recs) > 0
        assert all(isinstance(r, TaskRecommendation) for r in recs)
        names = [r.task_name for r in recs]
        assert "patch_smb" in names or "disable_smbv1" in names

    def test_failure_streak_penalises_priority(self):
        sa = SmartAutomation()
        sa.learn_from_history(self._make_history())
        findings = [
            Finding(title="SMB issue", description="ransomware vector",
                    severity=Severity.HIGH),
        ]
        recs = sa.recommend_tasks(findings, available_tasks=["patch_smb"])
        smb_recs = [r for r in recs if r.task_name == "patch_smb"]
        if smb_recs:
            assert smb_recs[0].estimated_success < 0.7  # penalised

    def test_suggest_schedule_unknown_task(self):
        sa = SmartAutomation()
        sched = sa.suggest_schedule("unknown_task")
        assert sched["confidence"] == "low"

    def test_suggest_schedule_with_failures(self):
        sa = SmartAutomation()
        sa.learn_from_history(self._make_history())
        sched = sa.suggest_schedule("patch_smb")
        # Should back off due to failure streak
        assert sched["interval_hours"] > 24

    def test_estimate_success_no_history(self):
        sa = SmartAutomation()
        # Unknown task defaults to 0.7 prior
        prob = sa._estimate_success(None)
        assert prob == pytest.approx(0.7)


# ===================================================================
# AIEngine Integration
# ===================================================================


class TestAIEngineIntegration:
    """Tests for the new methods wired into AIEngine."""

    @pytest.fixture
    def engine(self):
        config = Config()
        bus = EventBus()
        from network_guardian.ai import AIEngine
        return AIEngine(config, bus)

    @pytest.mark.asyncio
    async def test_forecast_arima(self, engine):
        import random
        rng = random.Random(1)
        series = [10 + 0.5 * i + rng.gauss(0, 0.5) for i in range(80)]
        result = await engine.forecast(series, steps=5, method="arima")
        assert len(result.points) == 5
        assert result.method == "arima"

    @pytest.mark.asyncio
    async def test_forecast_seasonal(self, engine):
        import random, math
        rng = random.Random(2)
        series = [10 + 3 * math.sin(2 * math.pi * i / 24) + rng.gauss(0, 0.3) for i in range(100)]
        result = await engine.forecast(series, steps=10, method="seasonal", period=24)
        assert len(result.points) == 10

    @pytest.mark.asyncio
    async def test_analyse_fleet(self, engine):
        hosts = [
            Host(ip="10.0.0.1", status=HostStatus.UP, open_ports=[22, 443]),
            Host(ip="10.0.0.2", status=HostStatus.UP, open_ports=[22, 80, 443]),
            Host(ip="10.0.0.3", status=HostStatus.UP, open_ports=[22, 443]),
            Host(ip="10.0.0.4", status=HostStatus.UP, open_ports=[22, 443]),
            Host(ip="10.0.0.5", status=HostStatus.UP, open_ports=[21, 23, 445, 3389, 5900]),
        ]
        profiles = await engine.analyse_fleet(hosts)
        assert len(profiles) == 5

    @pytest.mark.asyncio
    async def test_recommend_tasks(self, engine):
        findings = [
            Finding(title="Open SMB port", description="SMB on 445", severity=Severity.HIGH),
        ]
        recs = await engine.recommend_tasks(findings, available_tasks=["patch_smb", "firewall_audit"])
        assert isinstance(recs, list)

    @pytest.mark.asyncio
    async def test_get_forecaster_caches(self, engine):
        f1 = engine.get_forecaster("arima")
        f2 = engine.get_forecaster("arima")
        assert f1 is f2

    @pytest.mark.asyncio
    async def test_get_forecaster_invalid(self, engine):
        with pytest.raises(ValueError):
            engine.get_forecaster("nonexistent")

    def test_audit_analyzer_property(self, engine):
        assert engine.audit_analyzer is not None
        assert engine.audit_analyzer is engine.audit_analyzer  # cached

    def test_smart_automation_property(self, engine):
        assert engine.smart_automation is not None
        assert engine.smart_automation is engine.smart_automation  # cached
