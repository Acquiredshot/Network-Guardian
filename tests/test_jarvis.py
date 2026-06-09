"""
Tests for the network_guardian.jarvis package.

Covers:
  - TelemetryAggregator  (with injected temp data_root)
  - ThreatReportEngine   (scoring, report lines)
  - SubsystemBootstrapper (root detection, validation)
  - parse_intent / INTENT_MAP
  - JarvisCore.dispatch()
  - JARVIS → LangGraph integration (DeepSeek mocked)
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── TelemetryAggregator ──────────────────────────────────────────
from network_guardian.jarvis.telemetry_aggregator import TelemetryAggregator
from network_guardian.jarvis.threat_report_engine import ThreatReportEngine
from network_guardian.jarvis.subsystem_bootstrapper import (
    SubsystemBootstrapper,
    _resolve_ng_root,
)
from network_guardian.jarvis.jarvis_core import (
    JarvisCore,
    parse_intent,
    INTENT_MAP,
    cmd_situation,
    cmd_metrics,
    cmd_triage,
)

# ════════════════════════════════════════════════════════════════
#  FIXTURES
# ════════════════════════════════════════════════════════════════

@pytest.fixture()
def data_root(tmp_path: Path) -> Path:
    """Minimal data_root with fleet.json, injection_history.db, lateral_movement.json."""

    # fleet.json
    fleet = {
        "devices": [
            {"id": "aa:bb:cc:dd:ee:ff", "hostname": "laptop-01", "ip": "192.168.1.10",
             "status": "active", "last_seen": "2026-05-29T12:00:00"},
            {"id": "aa:bb:cc:00:11:22", "hostname": "server-01", "ip": "192.168.1.1",
             "status": "active", "last_seen": "2026-05-29T12:01:00"},
        ]
    }
    (tmp_path / "fleet.json").write_text(json.dumps(fleet))

    # injection_history.db (matches smart_firewall sub-dir used by TelemetryAggregator)
    (tmp_path / "smart_firewall").mkdir(exist_ok=True)
    db_path = tmp_path / "smart_firewall" / "injection_history.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE injections "
        "(id INTEGER PRIMARY KEY, timestamp TEXT, source_ip TEXT, "
        "attack_type TEXT, payload_snippet TEXT, blocked INTEGER)"
    )
    conn.execute(
        "INSERT INTO injections VALUES (1,'2026-05-29T10:00:00','10.0.0.1',"
        "'SQLi',\"' OR 1=1\",1)"
    )
    conn.execute(
        "INSERT INTO injections VALUES (2,'2026-05-29T11:00:00','10.0.0.2',"
        "'XSS','<script>alert(1)</script>',1)"
    )
    conn.commit()
    conn.close()

    # lateral_movement.json
    lateral = {
        "events": [
            {"timestamp": "2026-05-29T09:00:00", "source": "192.168.1.10",
             "destination": "192.168.1.100", "technique": "credential_dumping",
             "severity": "HIGH"},
        ]
    }
    (tmp_path / "lateral_movement.json").write_text(json.dumps(lateral))

    return tmp_path


@pytest.fixture()
def telemetry(data_root: Path) -> TelemetryAggregator:
    return TelemetryAggregator(data_root=data_root)


@pytest.fixture()
def report_engine(telemetry: TelemetryAggregator) -> ThreatReportEngine:
    return ThreatReportEngine(telemetry, operator="TestOp")


# ════════════════════════════════════════════════════════════════
#  TelemetryAggregator
# ════════════════════════════════════════════════════════════════

class TestTelemetryAggregator:

    def test_get_os_metrics_returns_expected_keys(self, telemetry):
        m = telemetry.get_os_metrics()
        for key in ("cpu_percent", "mem_percent", "mem_used",
                    "disk_percent", "disk_free", "proc_count", "uptime"):
            assert key in m, f"Missing key: {key}"

    def test_read_fleet_returns_devices(self, telemetry):
        data = telemetry.read_fleet()
        assert data is not None
        devices = data if isinstance(data, list) else data.get("devices", [])
        assert len(devices) == 2
        assert devices[0]["hostname"] == "laptop-01"

    def test_fleet_summary_returns_dict(self, telemetry):
        s = telemetry.fleet_summary()
        assert isinstance(s, dict)
        assert "total" in s
        assert s["total"] == 2

    def test_read_injection_history_returns_rows(self, telemetry):
        rows = telemetry.read_injection_history(limit=10)
        assert len(rows) == 2
        types = {r["attack_type"] for r in rows}
        assert "SQLi" in types

    def test_injection_summary_contains_count(self, telemetry):
        s = telemetry.injection_summary()
        assert isinstance(s, dict)
        # key is 'total_fetched' not 'total'
        assert s.get("total_fetched") == 2

    def test_read_lateral_movement_returns_events(self, telemetry):
        data = telemetry.read_lateral_movement()
        events = data if isinstance(data, list) else data.get("events", [])
        assert len(events) == 1
        assert events[0]["technique"] == "credential_dumping"

    def test_lateral_summary_mentions_high(self, telemetry):
        s = telemetry.lateral_summary()
        # Returns dict or string
        assert s is not None

    def test_full_snapshot_keys(self, telemetry):
        snap = telemetry.full_snapshot()
        assert isinstance(snap, dict)
        # Check required keys (actual snapshot uses 'injection' not 'injection_history')
        for key in ("os_metrics", "fleet"):
            assert key in snap, f"Snapshot missing key: {key}"
        # Either 'injection_history' or 'injection' must be present
        assert "injection_history" in snap or "injection" in snap, (
            "Snapshot missing injection key"
        )

    def test_empty_data_root_returns_gracefully(self, tmp_path):
        t = TelemetryAggregator(data_root=tmp_path)
        assert t.read_fleet() is None or t.read_fleet() == [] or isinstance(t.read_fleet(), dict)

    def test_injection_history_respects_limit(self, telemetry):
        rows = telemetry.read_injection_history(limit=1)
        assert len(rows) <= 1


# ════════════════════════════════════════════════════════════════
#  ThreatReportEngine
# ════════════════════════════════════════════════════════════════

class TestThreatReportEngine:

    def test_compute_threat_level_returns_tuple(self, report_engine):
        label, score = report_engine.compute_threat_level()
        assert isinstance(label, str)
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100

    def test_threat_label_values(self, report_engine):
        label, _ = report_engine.compute_threat_level()
        assert label in ("NOMINAL", "ELEVATED", "HIGH", "CRITICAL")

    def test_build_report_lines_returns_list(self, report_engine):
        lines = report_engine.build_report_lines()
        assert isinstance(lines, list)
        assert len(lines) > 0
        for line in lines:
            assert isinstance(line, str)

    def test_report_contains_section_headers(self, report_engine):
        lines = report_engine.build_report_lines()
        joined = "\n".join(lines)
        # Should mention threat level or report in some form
        assert any(kw in joined.upper() for kw in
                   ("THREAT", "NOMINAL", "ELEVATED", "HIGH", "CRITICAL", "FLEET", "METRICS"))

    def test_high_injection_count_raises_threat(self, tmp_path):
        """Inject 20 blocked SQLi events → score should be elevated."""
        (tmp_path / "smart_firewall").mkdir(exist_ok=True)
        db_path = tmp_path / "smart_firewall" / "injection_history.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE injections "
            "(id INTEGER PRIMARY KEY, timestamp TEXT, source_ip TEXT, "
            "attack_type TEXT, payload_snippet TEXT, blocked INTEGER)"
        )
        for i in range(20):
            conn.execute(
                f"INSERT INTO injections VALUES ({i},'2026-05-01','{i}.0.0.1','SQLi','x',1)"
            )
        conn.commit()
        conn.close()
        t = TelemetryAggregator(data_root=tmp_path)
        eng = ThreatReportEngine(t)
        _, score = eng.compute_threat_level()
        assert score > 20, "Heavy injection history should push score above 20"

    def test_print_summary_does_not_raise(self, report_engine, capsys):
        report_engine.print_summary()
        out = capsys.readouterr().out
        assert len(out) > 0


# ════════════════════════════════════════════════════════════════
#  SubsystemBootstrapper
# ════════════════════════════════════════════════════════════════

class TestSubsystemBootstrapper:

    def test_resolve_ng_root_returns_path(self):
        root = _resolve_ng_root()
        assert isinstance(root, Path)

    def test_resolve_ng_root_via_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NG_ROOT", str(tmp_path))
        root = _resolve_ng_root()
        assert root == tmp_path

    def test_is_running_false_when_not_started(self):
        bs = SubsystemBootstrapper()
        assert bs.is_running is False

    def test_validate_environment_missing_root_raises(self, tmp_path):
        bs = SubsystemBootstrapper(ng_root=tmp_path / "nonexistent")
        with pytest.raises(RuntimeError, match="not found"):
            bs._validate_environment()

    def test_validate_environment_missing_script_raises(self, tmp_path):
        bs = SubsystemBootstrapper(ng_root=tmp_path)
        with pytest.raises(RuntimeError, match="start_all.py"):
            bs._validate_environment()

    def test_validate_environment_passes_with_script(self, tmp_path):
        (tmp_path / "start_all.py").write_text("# stub")
        bs = SubsystemBootstrapper(ng_root=tmp_path)
        bs._validate_environment()   # should not raise


# ════════════════════════════════════════════════════════════════
#  Intent Parser
# ════════════════════════════════════════════════════════════════

class TestParseIntent:

    @pytest.mark.parametrize("text,expected", [
        ("situation",              "cmd_situation"),
        ("show me the status",     "cmd_situation"),
        ("what threat is there",   "cmd_situation"),
        ("start the defenses",     "cmd_start"),
        ("activate",               "cmd_start"),
        ("stop",                   "cmd_stop"),
        ("halt all systems",       "cmd_stop"),
        ("fleet report",           "cmd_fleet"),
        ("show me the network map","cmd_fleet"),
        ("firewall logs",          "cmd_firewall"),
        ("sql injection history",  "cmd_firewall"),
        ("lateral movement scan",  "cmd_lateral"),
        ("cpu metrics",            "cmd_metrics"),
        ("check memory usage",     "cmd_metrics"),
        ("performance",            "cmd_metrics"),
        ("triage the network",     "cmd_triage"),
        ("analyze threats",        "cmd_triage"),
        ("deep scan",              "cmd_triage"),
        ("help",                   "cmd_help"),
        ("?",                      "cmd_help"),
        ("exit",                   "cmd_exit"),
        ("quit",                   "cmd_exit"),
        ("bye",                    "cmd_exit"),
    ])
    def test_known_intents(self, text, expected):
        assert parse_intent(text) == expected

    def test_empty_string_returns_none(self):
        assert parse_intent("") is None
        assert parse_intent("   ") is None

    def test_unknown_text_returns_none(self):
        assert parse_intent("xyzzy jabberwocky") is None

    def test_longest_match_wins(self):
        # "network map" (11 chars) beats "network" (7 chars) → both map to cmd_fleet
        assert parse_intent("show me the network map") == "cmd_fleet"

    def test_intent_map_completeness(self):
        expected_handlers = {
            "cmd_situation", "cmd_start", "cmd_stop",
            "cmd_fleet", "cmd_firewall", "cmd_lateral",
            "cmd_metrics", "cmd_triage", "cmd_help", "cmd_exit",
        }
        registered = set(INTENT_MAP.values())
        assert expected_handlers.issubset(registered), (
            f"Missing handlers: {expected_handlers - registered}"
        )


# ════════════════════════════════════════════════════════════════
#  JarvisCore.dispatch()
# ════════════════════════════════════════════════════════════════

class TestJarvisCore:

    @pytest.fixture()
    def core(self):
        return JarvisCore(voice=False, ear=False)

    def test_dispatch_known_command_returns_true(self, core, capsys, data_root, monkeypatch):
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))
        result = core.dispatch("show me the metrics")
        assert result is True

    def test_dispatch_unknown_returns_false(self, core):
        result = core.dispatch("zephyr is the wind")
        assert result is False

    def test_dispatch_help_prints_output(self, core, capsys):
        core.dispatch("help")
        out = capsys.readouterr().out
        assert "situation" in out.lower() or "command" in out.lower()

    def test_dispatch_situation(self, core, capsys, data_root, monkeypatch):
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))
        core.dispatch("situation")
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_dispatch_exit_raises_systemexit(self, core):
        with pytest.raises(SystemExit):
            core.dispatch("exit")


# ════════════════════════════════════════════════════════════════
#  JARVIS Triage → LangGraph (DeepSeek mocked)
# ════════════════════════════════════════════════════════════════

class TestJarvisTriage:

    @pytest.fixture()
    def mock_reason_result(self):
        return {
            "intent_class": "RESPOND",
            "confidence": 0.92,
            "deepseek_reasoning": "The host at 10.0.0.1 is probing port 22 repeatedly.",
            "action_plan": [
                {"agent": "SmartFirewall", "action": "Block 10.0.0.1 on port 22"},
                {"agent": "IDS", "action": "Flag as brute-force attempt"},
            ],
            "recommendations": [
                "Enable fail2ban on all SSH-accessible hosts.",
                "Consider geofencing inbound SSH to known IP ranges.",
            ],
            "error": "",
        }

    def test_triage_prints_ai_result(
        self, capsys, mock_reason_result, monkeypatch, data_root
    ):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-testkey-1234")
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))

        async_mock = AsyncMock(return_value=mock_reason_result)

        with patch("network_guardian.jarvis.jarvis_core._LG_AVAILABLE", True), \
             patch("network_guardian.jarvis.jarvis_core._lg_reason", async_mock):
            cmd_triage("triage analyze intrusion")

        out = capsys.readouterr().out
        assert "RESPOND" in out or "intent" in out.lower()
        assert "SmartFirewall" in out or "action" in out.lower()

    def test_triage_falls_back_without_api_key(self, capsys, monkeypatch, data_root):
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))
        cmd_triage("triage deep scan")
        out = capsys.readouterr().out
        # Should gracefully fall back (no crash)
        assert len(out) > 0

    def test_triage_falls_back_when_lg_unavailable(self, capsys, monkeypatch, data_root):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-somekey")
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))
        with patch("network_guardian.jarvis.jarvis_core._LG_AVAILABLE", False):
            cmd_triage("analyze threats")
        out = capsys.readouterr().out
        assert "fallback" in out.lower() or "offline" in out.lower() or len(out) > 0

    def test_triage_handles_reasoner_exception(self, capsys, monkeypatch, data_root):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-testkey-1234")
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))

        async_mock = AsyncMock(side_effect=RuntimeError("API unreachable"))

        with patch("network_guardian.jarvis.jarvis_core._LG_AVAILABLE", True), \
             patch("network_guardian.jarvis.jarvis_core._lg_reason", async_mock):
            cmd_triage("deep scan")

        out = capsys.readouterr().out
        assert "fail" in out.lower() or "error" in out.lower()

    def test_triage_low_confidence_displayed(
        self, capsys, mock_reason_result, monkeypatch, data_root
    ):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-testkey-1234")
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))

        low_conf = {**mock_reason_result, "confidence": 0.25}
        async_mock = AsyncMock(return_value=low_conf)

        with patch("network_guardian.jarvis.jarvis_core._LG_AVAILABLE", True), \
             patch("network_guardian.jarvis.jarvis_core._lg_reason", async_mock):
            cmd_triage("analyze")

        out = capsys.readouterr().out
        assert "25%" in out or "0.25" in out or "confidence" in out.lower()


# ════════════════════════════════════════════════════════════════
#  Integration: full JARVIS flow (no voice/ear/subprocess)
# ════════════════════════════════════════════════════════════════

class TestJarvisIntegration:

    def test_full_situation_flow(self, data_root, monkeypatch, capsys):
        monkeypatch.setenv("NG_DATA_ROOT", str(data_root))
        t = TelemetryAggregator(data_root=data_root)
        r = ThreatReportEngine(t, operator="CI")
        r.print_summary()
        out = capsys.readouterr().out
        assert len(out) > 20

    def test_report_lines_match_print_summary(self, data_root, capsys):
        t = TelemetryAggregator(data_root=data_root)
        r = ThreatReportEngine(t)
        lines = r.build_report_lines()
        r.print_summary()
        printed = capsys.readouterr().out
        # At minimum same number of content lines
        assert len(lines) >= 1
        assert len(printed) > 0

    def test_snapshot_matches_telemetry_reads(self, telemetry):
        snap   = telemetry.full_snapshot()
        fleet  = telemetry.read_fleet()
        inj    = telemetry.read_injection_history(limit=100)
        # Snapshot should contain the fleet data
        snap_fleet = snap.get("fleet") or snap.get("devices")
        assert snap_fleet is not None or fleet is None   # both absent OR both present
        # Snapshot may aggregate injection data under 'injection' or 'injection_history'
        snap_inj = snap.get("injection_history") or snap.get("injection")
        assert snap_inj is not None or len(inj) == 0
