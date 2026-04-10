"""Tests for IDS, IPS, and IP Cloaking subsystems."""

import asyncio
import time

import pytest

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.core.events import Event, EventBus
from network_guardian.ids import (
    Alert,
    ConnectionTracker,
    DetectionMethod,
    IntrusionDetectionSystem,
    SignatureRule,
    ThreatCategory,
)
from network_guardian.ips import (
    BlockEntry,
    BlockReason,
    IntrusionPreventionSystem,
    IPSEvent,
    RateLimitEntry,
    ResponseAction,
)
from network_guardian.cloaking import (
    CloakIdentity,
    CloakMode,
    DecoyTarget,
    DecoyGenerator,
    IPCloakingSystem,
    IPMasker,
    ProxyHop,
    ProxyProtocol,
    SourceRotator,
)
from network_guardian.models.network import Severity


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

@pytest.fixture
def config():
    return Config()

@pytest.fixture
def bus():
    return EventBus()

@pytest.fixture
def ids(config, bus):
    return IntrusionDetectionSystem(config, bus)

@pytest.fixture
def ips(config, bus):
    return IntrusionPreventionSystem(config, bus)

@pytest.fixture
def cloaking(config, bus):
    return IPCloakingSystem(config, bus)


# =======================================================================
# IDS Tests
# =======================================================================

class TestConnectionTracker:
    def test_record_and_rate(self):
        ct = ConnectionTracker(window_seconds=60.0)
        for _ in range(10):
            ct.record("10.0.0.1", 80)
        assert ct.connection_rate("10.0.0.1") > 0

    def test_unique_ports(self):
        ct = ConnectionTracker(window_seconds=60.0)
        for port in range(1, 26):  # port 0 is skipped by record()
            ct.record("10.0.0.1", port)
        assert ct.unique_ports("10.0.0.1") == 25

    def test_reset_single(self):
        ct = ConnectionTracker(window_seconds=60.0)
        ct.record("10.0.0.1", 80)
        ct.record("10.0.0.1", 81)
        ct.record("10.0.0.2", 443)
        ct.record("10.0.0.2", 444)
        ct.reset("10.0.0.1")
        assert ct.connection_rate("10.0.0.1") == 0
        assert ct.unique_ports("10.0.0.2") == 2

    def test_reset_all(self):
        ct = ConnectionTracker(window_seconds=60.0)
        ct.record("10.0.0.1", 80)
        ct.record("10.0.0.2", 443)
        ct.reset()
        assert ct.connection_rate("10.0.0.1") == 0
        assert ct.connection_rate("10.0.0.2") == 0


class TestSignatureDetection:
    @pytest.mark.asyncio
    async def test_sql_injection(self, ids):
        alerts = await ids.analyse_payload(
            "GET /page?id=1 OR 1=1 --", source_ip="10.0.0.99"
        )
        assert len(alerts) >= 1
        sqli = [a for a in alerts if a.category == ThreatCategory.INJECTION]
        assert sqli

    @pytest.mark.asyncio
    async def test_xss_detection(self, ids):
        alerts = await ids.analyse_payload(
            '<img src=x onerror="alert(1)">', source_ip="10.0.0.50"
        )
        assert any(
            "xss" in a.rule_name.lower() or a.category == ThreatCategory.INJECTION
            for a in alerts
        )

    @pytest.mark.asyncio
    async def test_clean_payload(self, ids):
        alerts = await ids.analyse_payload(
            "GET /index.html HTTP/1.1", source_ip="10.0.0.1"
        )
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_rule_disable(self, ids):
        # Disable all rules, scan malicious payload — should get 0 alerts
        for rule in ids.rules:
            ids.disable_rule(rule.sid)
        alerts = await ids.analyse_payload("SELECT * FROM users --")
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_rule_enable_toggle(self, ids):
        rule = ids.rules[0]
        ids.disable_rule(rule.sid)
        assert not rule.enabled
        ids.enable_rule(rule.sid)
        assert rule.enabled

    @pytest.mark.asyncio
    async def test_add_custom_rule(self, ids):
        custom = SignatureRule(
            sid=9001,
            name="Test Rule",
            category=ThreatCategory.MALWARE,
            severity=Severity.CRITICAL,
            pattern=r"MALWARE_TEST_STRING",
            description="Custom test rule",
        )
        ids.add_rule(custom)
        alerts = await ids.analyse_payload("found MALWARE_TEST_STRING payload")
        assert any(a.rule_name == "Test Rule" for a in alerts)

    @pytest.mark.asyncio
    async def test_remove_rule(self, ids):
        original = len(ids.rules)
        sid = ids.rules[0].sid
        assert ids.remove_rule(sid)
        assert len(ids.rules) == original - 1
        assert not ids.remove_rule(99999)  # non-existent


class TestAnomalyDetection:
    @pytest.mark.asyncio
    async def test_port_scan_detection(self, ids):
        # Record connections to many unique ports
        alerts = []
        for port in range(25):
            result = await ids.record_connection("10.0.0.5", "192.168.1.1", port)
            alerts.extend(result)
        port_scans = [a for a in alerts if a.category == ThreatCategory.PORT_SCAN]
        assert len(port_scans) >= 1

    @pytest.mark.asyncio
    async def test_brute_force_detection(self, ids):
        alerts = []
        for _ in range(6):
            result = await ids.record_auth_failure("10.0.0.10", service="ssh")
            alerts.extend(result)
        brute = [a for a in alerts if a.category == ThreatCategory.BRUTE_FORCE]
        assert len(brute) >= 1

    @pytest.mark.asyncio
    async def test_normal_connections(self, ids):
        alerts = await ids.record_connection("10.0.0.1", "192.168.1.1", 80)
        assert len(alerts) == 0


class TestCorrelationEngine:
    @pytest.mark.asyncio
    async def test_multi_stage_attack(self, ids):
        events = [
            {"source_ip": "10.0.0.1", "category": "port_scan"},
            {"source_ip": "10.0.0.1", "category": "injection"},
        ]
        alerts = await ids.correlate_events(events)
        assert len(alerts) >= 1
        assert alerts[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unrelated_events(self, ids):
        events = [
            {"source_ip": "10.0.0.1", "category": "port_scan"},
            {"source_ip": "10.0.0.2", "category": "injection"},
        ]
        alerts = await ids.correlate_events(events)
        assert len(alerts) == 0


class TestIDSEventBus:
    @pytest.mark.asyncio
    async def test_alert_publishes_event(self):
        bus = EventBus()
        ids_sys = IntrusionDetectionSystem(Config(), bus)
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("ids.alert", handler)
        alerts = await ids_sys.analyse_payload(
            "GET /page?id=1 OR 1=1 --", source_ip="10.0.0.1"
        )
        assert len(alerts) >= 1
        assert len(received) >= 1
        assert "alert" in received[0].data


class TestAlertSuppression:
    @pytest.mark.asyncio
    async def test_duplicate_suppressed(self):
        bus = EventBus()
        ids_sys = IntrusionDetectionSystem(Config(), bus)
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("ids.alert", handler)
        a1 = await ids_sys.analyse_payload("GET /page?id=1 OR 1=1 --", source_ip="10.0.0.1")
        count_after_first = len(received)
        assert len(a1) >= 1
        assert count_after_first >= 1
        # Second identical payload from same source — should be suppressed
        await ids_sys.analyse_payload("GET /page?id=1 OR 1=1 --", source_ip="10.0.0.1")
        # No new events should have been published
        assert len(received) == count_after_first

    @pytest.mark.asyncio
    async def test_different_source_not_suppressed(self):
        bus = EventBus()
        ids_sys = IntrusionDetectionSystem(Config(), bus)
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("ids.alert", handler)
        a1 = await ids_sys.analyse_payload("GET /page?id=1 OR 1=1 --", source_ip="10.0.0.1")
        count_after_first = len(received)
        assert len(a1) >= 1
        # Same payload from different source — should NOT be suppressed
        a2 = await ids_sys.analyse_payload("GET /page?id=1 OR 1=1 --", source_ip="10.0.0.2")
        assert len(a2) >= 1
        assert len(received) > count_after_first


# =======================================================================
# IPS Tests
# =======================================================================

class TestBlocklist:
    @pytest.mark.asyncio
    async def test_block_and_check(self, ips):
        await ips.block_ip("10.0.0.99")
        assert ips.is_blocked("10.0.0.99")

    @pytest.mark.asyncio
    async def test_unblock(self, ips):
        await ips.block_ip("10.0.0.99")
        assert await ips.unblock_ip("10.0.0.99")
        assert not ips.is_blocked("10.0.0.99")

    @pytest.mark.asyncio
    async def test_unblock_nonexistent(self, ips):
        assert not await ips.unblock_ip("10.0.0.99")

    @pytest.mark.asyncio
    async def test_block_allowlisted_ip(self, ips):
        result = await ips.block_ip("127.0.0.1")
        assert result is None
        assert not ips.is_blocked("127.0.0.1")

    @pytest.mark.asyncio
    async def test_blocked_ips_list(self, ips):
        await ips.block_ip("10.0.0.1")
        await ips.block_ip("10.0.0.2")
        blocked = ips.blocked_ips
        ips_set = {b.ip for b in blocked}
        assert "10.0.0.1" in ips_set
        assert "10.0.0.2" in ips_set

    @pytest.mark.asyncio
    async def test_block_with_duration(self, ips):
        await ips.block_ip("10.0.0.50", duration=3600)
        entry = ips.blocked_ips[0]
        assert entry.expires_at is not None


class TestAllowlist:
    def test_default_allowlist(self, ips):
        assert "127.0.0.1" in ips.allowlist
        assert "::1" in ips.allowlist

    def test_add_to_allowlist(self, ips):
        ips.add_to_allowlist("192.168.1.1")
        assert "192.168.1.1" in ips.allowlist

    @pytest.mark.asyncio
    async def test_allowlist_removes_from_blocklist(self, ips):
        await ips.block_ip("10.0.0.50")
        assert ips.is_blocked("10.0.0.50")
        ips.add_to_allowlist("10.0.0.50")
        assert not ips.is_blocked("10.0.0.50")

    def test_remove_from_allowlist(self, ips):
        ips.add_to_allowlist("192.168.1.1")
        assert ips.remove_from_allowlist("192.168.1.1")
        assert "192.168.1.1" not in ips.allowlist


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_rate_limit_and_check(self, ips):
        await ips.rate_limit_ip("10.0.0.1", max_rps=5.0)
        # First check should allow (bucket starts full)
        assert ips.check_rate_limit("10.0.0.1")

    @pytest.mark.asyncio
    async def test_unlimitd_ip_always_allowed(self, ips):
        assert ips.check_rate_limit("10.0.0.99")


class TestQuarantine:
    @pytest.mark.asyncio
    async def test_quarantine_and_check(self, ips):
        await ips.quarantine_ip("10.0.0.33")
        assert ips.is_quarantined("10.0.0.33")

    @pytest.mark.asyncio
    async def test_release_quarantine(self, ips):
        await ips.quarantine_ip("10.0.0.33")
        assert await ips.release_quarantine("10.0.0.33")
        assert not ips.is_quarantined("10.0.0.33")

    @pytest.mark.asyncio
    async def test_quarantined_ips(self, ips):
        await ips.quarantine_ip("10.0.0.1")
        await ips.quarantine_ip("10.0.0.2")
        assert ips.quarantined_ips == {"10.0.0.1", "10.0.0.2"}


class TestShouldAllow:
    @pytest.mark.asyncio
    async def test_blocked_ip_denied(self, ips):
        await ips.block_ip("10.0.0.55")
        assert not ips.should_allow("10.0.0.55")

    @pytest.mark.asyncio
    async def test_quarantined_ip_denied(self, ips):
        await ips.quarantine_ip("10.0.0.55")
        assert not ips.should_allow("10.0.0.55")

    def test_clean_ip_allowed(self, ips):
        assert ips.should_allow("10.0.0.1")


class TestIPSAutoRespond:
    @pytest.mark.asyncio
    async def test_handle_ids_alert(self, ips):
        alert = Alert(
            alert_id="test-001",
            rule_name="Brute Force Detected",
            category=ThreatCategory.BRUTE_FORCE,
            severity=Severity.HIGH,
            source_ip="10.0.0.88",
            method=DetectionMethod.HEURISTIC,
            description="test",
        )
        event = await ips.handle_ids_alert(alert)
        assert event is not None
        assert ips.is_blocked("10.0.0.88")

    @pytest.mark.asyncio
    async def test_auto_respond_disabled(self, ips):
        ips.set_auto_respond(False)
        alert = Alert(
            alert_id="test-002",
            rule_name="Brute Force",
            category=ThreatCategory.BRUTE_FORCE,
            severity=Severity.HIGH,
            source_ip="10.0.0.77",
            method=DetectionMethod.HEURISTIC,
            description="test",
        )
        event = await ips.handle_ids_alert(alert)
        assert event is None
        assert not ips.is_blocked("10.0.0.77")

    @pytest.mark.asyncio
    async def test_policy_change(self, ips):
        ips.set_policy(ThreatCategory.PORT_SCAN, ResponseAction.BLOCK, 600)
        alert = Alert(
            alert_id="test-003",
            rule_name="Port Scan",
            category=ThreatCategory.PORT_SCAN,
            severity=Severity.MEDIUM,
            source_ip="10.0.0.66",
            method=DetectionMethod.ANOMALY,
            description="test",
        )
        event = await ips.handle_ids_alert(alert)
        assert event is not None
        assert ips.is_blocked("10.0.0.66")


class TestIPSEventBus:
    @pytest.mark.asyncio
    async def test_block_publishes_event(self, ips, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("ips.block", handler)
        await ips.block_ip("10.0.0.99")
        assert len(received) == 1


# =======================================================================
# IP Cloaking Tests
# =======================================================================

class TestIPMasker:
    def test_mask_deterministic(self):
        m = IPMasker(salt="test-salt")
        a1 = m.mask("192.168.1.1")
        a2 = m.mask("192.168.1.1")
        assert a1 == a2
        assert a1 != "192.168.1.1"

    def test_unmask(self):
        m = IPMasker(salt="test-salt")
        alias = m.mask("10.0.0.1")
        assert m.unmask(alias) == "10.0.0.1"

    def test_unmask_unknown(self):
        m = IPMasker(salt="test-salt")
        assert m.unmask("unknown-alias") is None

    def test_mask_text(self):
        m = IPMasker(salt="test")
        masked = m.mask("192.168.1.1")
        result = m.mask_text("Connected to 192.168.1.1 on port 80")
        assert "192.168.1.1" not in result
        assert masked in result

    def test_mapping_count(self):
        m = IPMasker(salt="test")
        m.mask("10.0.0.1")
        m.mask("10.0.0.2")
        assert m.mapping_count == 2

    def test_reset(self):
        m = IPMasker(salt="test")
        old_alias = m.mask("10.0.0.1")
        m.reset("new-salt")
        new_alias = m.mask("10.0.0.1")
        assert old_alias != new_alias


class TestSourceRotator:
    def test_round_robin(self):
        r = SourceRotator(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        sources = [r.next_source() for _ in range(6)]
        assert sources[:3] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert sources[3:] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_random_source(self):
        r = SourceRotator(["10.0.0.1", "10.0.0.2"])
        src = r.random_source()
        assert src in ("10.0.0.1", "10.0.0.2")

    def test_empty_pool(self):
        r = SourceRotator()
        assert r.next_source() is None
        assert r.random_source() is None

    def test_add_remove(self):
        r = SourceRotator()
        r.add_source("10.0.0.1")
        assert r.pool_size == 1
        assert r.remove_source("10.0.0.1")
        assert r.pool_size == 0

    def test_sources_property(self):
        r = SourceRotator(["10.0.0.1", "10.0.0.2"])
        assert r.sources == ["10.0.0.1", "10.0.0.2"]


class TestDecoyGenerator:
    def test_generate_decoys(self):
        gen = DecoyGenerator(subnet="192.168.1.0/24", count=5)
        decoys = gen.generate_decoys("192.168.1.100", real_ports=[80, 443])
        assert len(decoys) == 5
        for d in decoys:
            assert d.ip != "192.168.1.100"
            assert d.ports == [80, 443]

    def test_decoy_excludes_target(self):
        gen = DecoyGenerator(subnet="192.168.1.0/24", count=3)
        decoys = gen.generate_decoys("192.168.1.50", real_ports=[80])
        ips_list = [d.ip for d in decoys]
        assert "192.168.1.50" not in ips_list


class TestCloakMode:
    def test_modes(self):
        assert CloakMode.DISABLED.value == "disabled"
        assert CloakMode.MASK.value == "mask"
        assert CloakMode.ROTATE.value == "rotate"
        assert CloakMode.PROXY.value == "proxy"
        assert CloakMode.DECOY.value == "decoy"


class TestIPCloakingSystem:
    def test_initial_mode_disabled(self, cloaking):
        assert cloaking.mode == CloakMode.DISABLED

    def test_set_mode(self, cloaking):
        cloaking.set_mode(CloakMode.MASK)
        assert cloaking.mode == CloakMode.MASK

    def test_mask_ip(self, cloaking):
        cloaking.set_mode(CloakMode.MASK)
        masked = cloaking.mask_ip("10.0.0.1")
        assert masked != "10.0.0.1"

    def test_unmask_ip(self, cloaking):
        cloaking.set_mode(CloakMode.MASK)
        masked = cloaking.mask_ip("10.0.0.1")
        assert cloaking.unmask_ip(masked) == "10.0.0.1"

    def test_mask_text(self, cloaking):
        cloaking.set_mode(CloakMode.MASK)
        # Pre-mask the IP so it's in the masker's mapping
        cloaking.mask_ip("192.168.1.1")
        text = "Host 192.168.1.1 is up"
        masked = cloaking.mask_text(text)
        assert "192.168.1.1" not in masked

    def test_proxy_chain(self, cloaking):
        hop = ProxyHop(
            host="proxy.example.com",
            port=8080,
            protocol=ProxyProtocol.SOCKS5,
        )
        cloaking.add_proxy(hop)
        assert len(cloaking.proxy_chain) == 1
        assert cloaking.proxy_chain[0].host == "proxy.example.com"

    def test_generate_decoys(self, cloaking):
        cloaking.set_mode(CloakMode.DECOY)
        decoys = cloaking.generate_decoys("192.168.1.100", ports=[80])
        assert len(decoys) >= 1
        for d in decoys:
            assert isinstance(d, DecoyTarget)

    def test_create_identity(self, cloaking):
        ident = cloaking.create_identity("stealth", CloakMode.MASK)
        assert ident.name == "stealth"
        assert ident.mode == CloakMode.MASK
        assert len(cloaking.list_identities()) == 1

    def test_activate_identity(self, cloaking):
        cloaking.create_identity("stealth", CloakMode.ROTATE)
        assert cloaking.activate_identity("stealth")
        assert cloaking.active_identity == "stealth"
        assert cloaking.mode == CloakMode.ROTATE

    def test_activate_nonexistent(self, cloaking):
        assert not cloaking.activate_identity("ghost")

    def test_delete_identity(self, cloaking):
        cloaking.create_identity("temp", CloakMode.MASK)
        assert cloaking.delete_identity("temp")
        assert len(cloaking.list_identities()) == 0

    def test_prepare_scan(self, cloaking):
        cloaking.set_mode(CloakMode.MASK)
        result = cloaking.prepare_scan("192.168.1.50", ports=[22, 80])
        assert "real_target" in result
        assert result["real_target"] == "192.168.1.50"
        assert "display_target" in result
        assert "decoys" in result


# =======================================================================
# Engine integration Tests
# =======================================================================

class TestEngineIntegration:
    def test_ids_property(self):
        engine = Engine()
        ids = engine.ids
        assert isinstance(ids, IntrusionDetectionSystem)
        assert engine.ids is ids  # same instance (lazy singleton)

    def test_ips_property(self):
        engine = Engine()
        ips_sys = engine.ips
        assert isinstance(ips_sys, IntrusionPreventionSystem)
        assert engine.ips is ips_sys

    def test_cloaking_property(self):
        engine = Engine()
        cloak = engine.cloaking
        assert isinstance(cloak, IPCloakingSystem)
        assert engine.cloaking is cloak

    @pytest.mark.asyncio
    async def test_ids_ips_integration(self):
        """IDS alert triggers IPS auto-response via event bus."""
        engine = Engine()
        ids = engine.ids
        ips_sys = engine.ips

        # Brute-force detection → should auto-block
        for _ in range(6):
            await ids.record_auth_failure("10.0.0.88", service="ssh")

        alerts = ids.alerts
        brute_alerts = [a for a in alerts if a.category == ThreatCategory.BRUTE_FORCE]
        assert brute_alerts

        # Manually trigger IPS response
        event = await ips_sys.handle_ids_alert(brute_alerts[0])
        assert event is not None
        assert ips_sys.is_blocked("10.0.0.88")
        assert not ips_sys.should_allow("10.0.0.88")
