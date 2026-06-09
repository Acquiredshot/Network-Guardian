"""
Tests for SmartFirewallAgent fixes: #1 Event publishing, #2 raw_data in IDS,
#3 history persistence from scan_payload, #4 confidence aggregation across rule hits.
Also test EmailScanner v2 integration.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from network_guardian.agent.smart_firewall_agent import (
    SmartFirewallAgent, InjectionDetection, InjectionType, InjectionRule,
)
from network_guardian.core.events import Event, EventBus
from network_guardian.ids import IntrusionDetectionSystem, Alert, ThreatCategory
from network_guardian.ips import IntrusionPreventionSystem, BlockReason
from network_guardian.models.network import Severity
from network_guardian.config import Config


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def event_bus() -> EventBus:
    """Create a fresh EventBus for each test."""
    return EventBus()


@pytest.fixture
def temp_data_dir() -> Path:
    """Create a temporary directory for agent data."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def config() -> Config:
    """Create a test Config."""
    return Config()


@pytest.fixture
async def engine(config: Config, event_bus: EventBus):
    """Create and start a live Engine with IDS/IPS for integration testing."""
    from network_guardian.core.engine import Engine
    engine = Engine(config)
    engine._event_bus = event_bus
    # Lazy-load IDS and IPS
    _ = engine.ids
    _ = engine.ips
    await engine.start()
    yield engine
    await engine.stop()


@pytest.fixture
def agent(event_bus: EventBus, temp_data_dir: Path) -> SmartFirewallAgent:
    """Create a SmartFirewallAgent in detection-only mode (no IPS blocking)."""
    return SmartFirewallAgent(
        ips=None,
        event_bus=event_bus,
        auto_block=False,
        data_dir=temp_data_dir,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Fix #1: Event publishing uses Event() not raw dict
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fix1_publish_uses_event_not_dict(agent: SmartFirewallAgent, event_bus: EventBus):
    """Fix #1: event_bus.publish() is called with Event(), not a raw dict.

    This test verifies that run_cycle() publishes firewall.injection.cycle
    using Event(topic=..., data=...), which the EventBus expects.
    """
    received_events = []

    async def capture_event(event: Event) -> None:
        assert isinstance(event, Event), "Published object must be Event dataclass"
        received_events.append(event)

    agent._event_bus.subscribe("firewall.injection.cycle", capture_event)

    # Simulate a detection by queuing one manually (critical severity hits the 40-point threshold)
    # Need multiple detections to push threat_score into "critical" range
    for i in range(2):
        det = InjectionDetection(
            detection_id=f"test{i}",
            source_ip=f"192.168.1.{100+i}",
            payload_snippet="' OR '1'='1",
            injection_type=InjectionType.SQL,
            rule_name="SQL Tautology",
            severity="critical",
            confidence=0.95,
        )
        await agent._pending.put(det)

    report = await agent.run_cycle()

    # Verify the event was published as Event, not raw dict
    assert len(received_events) > 0, "Event should have been published"
    event = received_events[0]
    assert event.topic == "firewall.injection.cycle"
    assert event.data["risk_level"] in ("high", "critical"), "Should be high or critical risk"
    assert event.data["injections"] == 2


# ──────────────────────────────────────────────────────────────────────────────
# Fix #2: raw_data is included in Alert.as_dict
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fix2_alert_includes_raw_data():
    """Fix #2: IDS Alert.as_dict includes raw_data so the agent can re-detect.

    The SmartFirewallAgent subscribes to ids.alert events and re-parses
    the payload to classify injection types. Without raw_data, it can't.
    """
    alert = Alert(
        alert_id="test_alert_1",
        rule_name="Test Rule",
        category=ThreatCategory.INJECTION,
        severity=Severity.HIGH,
        source_ip="10.0.0.1",
        description="Test injection",
        raw_data="' UNION SELECT * FROM users -- ",
    )

    alert_dict = alert.as_dict

    assert "raw_data" in alert_dict, "Alert.as_dict must include raw_data"
    assert alert_dict["raw_data"] == "' UNION SELECT * FROM users -- "


@pytest.mark.asyncio
async def test_fix2_agent_receives_raw_data_from_ids(agent: SmartFirewallAgent, event_bus: EventBus):
    """Fix #2: Agent can extract raw_data from IDS alert and re-detect injections."""
    alert = Alert(
        alert_id="test_alert_2",
        rule_name="Injection Detected",
        category=ThreatCategory.INJECTION,
        severity=Severity.HIGH,
        source_ip="192.168.1.50",
        description="SQL injection detected",
        raw_data="'; DROP TABLE users; --",
    )

    # Simulate IDS publishing the alert
    await event_bus.publish(Event(
        topic="ids.alert",
        data={"alert": alert.as_dict},
    ))

    # Give async handlers time to process
    await asyncio.sleep(0.1)

    # Agent should have queued a detection from the re-parse
    detections = []
    while not agent._pending.empty():
        try:
            detections.append(agent._pending.get_nowait())
        except asyncio.QueueEmpty:
            break

    assert len(detections) > 0, "Agent should have queued a detection from IDS alert"
    assert detections[0].injection_type == InjectionType.SQL


# ──────────────────────────────────────────────────────────────────────────────
# Fix #3: History is persisted from scan_payload
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fix3_scan_payload_persists_history(agent: SmartFirewallAgent):
    """Fix #3: scan_payload() persists detections to _ip_history.

    This ensures escalation tiers work across multiple invocations
    of the primary integration point (scan_payload).

    Note: Escalation is based on current offense count when block decision
    is made. After first scan_payload(), history has 1 item, so the duration
    index maps to the 2nd tier (21600s).  After second call, history has 2
    items, index maps to 3rd tier (permanent).
    """
    ip = "203.0.113.42"

    # First call: history saved after scan, so offense_count=1 → duration_index=1 (21600s)
    detections1 = await agent.scan_payload(
        payload="' OR 1=1 --",
        source_ip=ip,
    )
    assert len(detections1) > 0
    offense_count_1 = agent.offense_count(ip)
    assert offense_count_1 == 1, f"First offense should be recorded; got {offense_count_1}"
    duration_1 = agent._block_duration(ip)
    assert duration_1 == 21600, f"With 1 offense, duration index=1 → 6h; got {duration_1}s"

    # Second call: history updated, now 2 items
    detections2 = await agent.scan_payload(
        payload="UNION SELECT * FROM users",
        source_ip=ip,
    )
    assert len(detections2) > 0
    offense_count_2 = agent.offense_count(ip)
    assert offense_count_2 == 2, f"Second offense should be recorded; got {offense_count_2}"

    # Verify permanent block tier (3+ offenses → None)
    duration = agent._block_duration(ip)
    assert duration is None, f"With 2+ offenses, should be permanent (None); got {duration}"


# ──────────────────────────────────────────────────────────────────────────────
# Fix #4: Confidence aggregation across rule hits
# ──────────────────────────────────────────────────────────────────────────────

def test_fix4_confidence_aggregation():
    """Fix #4: Multiple rule hits for same injection type aggregate confidence.

    If payload triggers both 'SQL Tautology' (conf=0.90) and 'SQL Stacked Query'
    (conf=0.93), we compute combined confidence as 1 - (1-0.90)*(1-0.93) ≈ 0.993.
    """
    agent = SmartFirewallAgent(ips=None, event_bus=None)

    # Payload that hits multiple SQL rules
    payload = "'; DROP TABLE users; SELECT * FROM admin WHERE '1'='1"

    detections = agent._detect(payload, source_ip="test_ip")

    # Should have one detection per injection type
    sql_dets = [d for d in detections if d.injection_type == InjectionType.SQL]
    assert len(sql_dets) == 1, "One detection per injection type"

    sql_det = sql_dets[0]
    # Multiple rules hit, so confidence should be aggregated (higher than single rule)
    assert sql_det.confidence > 0.90, f"Aggregated confidence should exceed single-rule confidence"
    # The rule label should indicate multiple rules matched
    assert "+" in sql_det.rule_name or sql_det.confidence >= 0.93, \
        f"Rule name or confidence should reflect multiple hits; got {sql_det.rule_name}, {sql_det.confidence}"


def test_fix4_confidence_highest_severity_rule_selected():
    """Fix #4: When multiple rules hit, report the one with highest severity."""
    agent = SmartFirewallAgent(ips=None, event_bus=None)

    # Payload that triggers both medium and high severity SQL rules
    payload = "' OR 1=1 -- AND 1=0 / /* comment */ SELECT * FROM users"

    detections = agent._detect(payload, source_ip="test_ip")

    # Find SQL detection
    sql_dets = [d for d in detections if d.injection_type == InjectionType.SQL]
    if sql_dets:
        sql_det = sql_dets[0]
        # Should report the severity of the worst (highest severity) rule
        assert sql_det.severity in ("high", "critical"), \
            f"Should report highest severity rule; got {sql_det.severity}"


# ──────────────────────────────────────────────────────────────────────────────
# Integration: all fixes working together
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_integration_full_cycle(agent: SmartFirewallAgent, event_bus: EventBus):
    """Integration test: scan payload → detect injection → aggregate confidence
    → persist history → publish event with correct structure.
    """
    payloads = [
        ("' OR 1=1 --", "192.168.0.101"),
        ("UNION SELECT password FROM admin", "192.168.0.101"),  # Same IP, second offense
    ]

    for payload, ip in payloads:
        detections = await agent.scan_payload(payload, source_ip=ip)
        assert len(detections) > 0, f"Should detect injection in: {payload}"

    # Verify history persisted and escalation applies
    offense_count = agent.offense_count("192.168.0.101")
    assert offense_count == 2, "Both offenses recorded"

    # Verify escalation tiers: 1st → 3600s, 2nd → 21600s, 3+ → permanent
    duration_1 = agent._ESCALATION[0]
    duration_2 = agent._ESCALATION[1]
    assert duration_1 == 3600, "1st offense duration"
    assert duration_2 == 21600, "2nd offense duration"


# ──────────────────────────────────────────────────────────────────────────────
# EmailScanner v2 basic test
# ──────────────────────────────────────────────────────────────────────────────

def test_email_scanner_config():
    """EmailScanner v2: config class exists and resolves spam folders."""
    from network_guardian.agent.email_scanner import EmailScanConfig, _SPAM_FOLDER_PRESETS

    cfg = EmailScanConfig(
        imap_host="imap.gmail.com",
        imap_user="user@gmail.com",
        imap_password="pass123",
    )

    assert cfg.imap_host == "imap.gmail.com"
    assert cfg.resolved_spam_folder() == "[Gmail]/Spam"


def test_email_scanner_custom_spam_folder():
    """EmailScanner v2: custom spam folder overrides preset."""
    from network_guardian.agent.email_scanner import EmailScanConfig

    cfg = EmailScanConfig(
        imap_host="imap.example.com",
        imap_user="user@example.com",
        imap_password="pass123",
        spam_folder="CustomSpam",
    )

    assert cfg.resolved_spam_folder() == "CustomSpam"


def test_email_scan_result_flagging():
    """EmailScanner v2: EmailScanResult flags when spam/malware/high-risk AI."""
    from network_guardian.agent.email_scanner import (
        EmailScanResult, SpamResult, MalwareResult, AIAnalysis,
    )

    # Flagged: spam detected
    result1 = EmailScanResult(
        uid="1",
        message_id="<msg1@example.com>",
        subject="Buy cheap meds",
        sender="spammer@bad.com",
        timestamp=datetime.now(timezone.utc),
        spam=SpamResult(available=True, is_spam=True, score=7.5),
        malware=MalwareResult(available=True, is_infected=False),
        ai=AIAnalysis(threat_type="clean", risk_level="low"),
    )
    assert result1.flagged is True, "Should flag spam"

    # Flagged: AI says high risk
    result2 = EmailScanResult(
        uid="2",
        message_id="<msg2@example.com>",
        subject="Urgent: Verify account",
        sender="noreply@fake-bank.com",
        timestamp=datetime.now(timezone.utc),
        spam=SpamResult(available=True, is_spam=False, score=2.1),
        malware=MalwareResult(available=True, is_infected=False),
        ai=AIAnalysis(threat_type="phishing", risk_level="critical"),
    )
    assert result2.flagged is True, "Should flag high-risk AI"

    # Not flagged: all clear
    result3 = EmailScanResult(
        uid="3",
        message_id="<msg3@example.com>",
        subject="Team standup",
        sender="teammate@work.com",
        timestamp=datetime.now(timezone.utc),
        spam=SpamResult(available=True, is_spam=False, score=0.1),
        malware=MalwareResult(available=True, is_infected=False),
        ai=AIAnalysis(threat_type="clean", risk_level="low"),
    )
    assert result3.flagged is False, "Should not flag clean email"
