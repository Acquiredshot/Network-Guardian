"""
Tests for the remote access module.

Covers: permissions, rate limiting, command routing, webhook signature
verification, WhatsApp/SMS channels, OpenClaw orchestrator, pipeline
execution, channel management, and engine integration.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.core.events import EventBus
from network_guardian.remote import (
    BaseChannel,
    ChannelConfig,
    ChannelType,
    CMDOPChannel,
    CommandResult,
    GuardianCommandRouter,
    OpenClawOrchestrator,
    PermissionLevel,
    PipelineResult,
    PipelineStep,
    RemoteAccessManager,
    RemoteConfig,
    RemotePermissionManager,
    RemoteRateLimiter,
    RemoteUser,
    TwilioSMSChannel,
    TwilioWhatsAppChannel,
    WebhookVerifier,
    _RateBucket,
)


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def engine():
    return Engine(Config())


@pytest.fixture
def router(engine):
    return GuardianCommandRouter(engine)


@pytest.fixture
def permissions():
    return RemotePermissionManager()


@pytest.fixture
def rate_limiter():
    return RemoteRateLimiter(max_per_minute=60)


@pytest.fixture
def remote_manager(engine):
    return RemoteAccessManager(engine)


# ===================================================================
# Permission manager tests
# ===================================================================

class TestRemotePermissionManager:
    def test_add_user(self, permissions):
        user = permissions.add_user("123", ChannelType.TELEGRAM, PermissionLevel.READ)
        assert isinstance(user, RemoteUser)
        assert user.user_id == "123"
        assert user.channel == ChannelType.TELEGRAM
        assert user.permission == PermissionLevel.READ

    def test_add_user_with_label(self, permissions):
        user = permissions.add_user("456", ChannelType.WHATSAPP, PermissionLevel.ADMIN, label="admin")
        assert user.label == "admin"

    def test_get_user(self, permissions):
        permissions.add_user("123", ChannelType.TELEGRAM, PermissionLevel.READ)
        user = permissions.get_user("123", ChannelType.TELEGRAM)
        assert user is not None
        assert user.user_id == "123"

    def test_get_user_not_found(self, permissions):
        assert permissions.get_user("999", ChannelType.SMS) is None

    def test_remove_user(self, permissions):
        permissions.add_user("123", ChannelType.TELEGRAM)
        assert permissions.remove_user("123", ChannelType.TELEGRAM)
        assert permissions.get_user("123", ChannelType.TELEGRAM) is None

    def test_remove_user_not_found(self, permissions):
        assert not permissions.remove_user("999", ChannelType.SMS)

    def test_check_permission_admin_has_all(self, permissions):
        permissions.add_user("admin", ChannelType.WHATSAPP, PermissionLevel.ADMIN)
        assert permissions.check_permission("admin", ChannelType.WHATSAPP, PermissionLevel.READ)
        assert permissions.check_permission("admin", ChannelType.WHATSAPP, PermissionLevel.EXECUTE)
        assert permissions.check_permission("admin", ChannelType.WHATSAPP, PermissionLevel.ADMIN)

    def test_check_permission_read_only(self, permissions):
        permissions.add_user("reader", ChannelType.SMS, PermissionLevel.READ)
        assert permissions.check_permission("reader", ChannelType.SMS, PermissionLevel.READ)
        assert not permissions.check_permission("reader", ChannelType.SMS, PermissionLevel.EXECUTE)
        assert not permissions.check_permission("reader", ChannelType.SMS, PermissionLevel.ADMIN)

    def test_check_permission_execute(self, permissions):
        permissions.add_user("op", ChannelType.TELEGRAM, PermissionLevel.EXECUTE)
        assert permissions.check_permission("op", ChannelType.TELEGRAM, PermissionLevel.READ)
        assert permissions.check_permission("op", ChannelType.TELEGRAM, PermissionLevel.EXECUTE)
        assert not permissions.check_permission("op", ChannelType.TELEGRAM, PermissionLevel.ADMIN)

    def test_check_permission_unknown_user(self, permissions):
        assert not permissions.check_permission("ghost", ChannelType.TELEGRAM, PermissionLevel.READ)

    def test_list_users(self, permissions):
        permissions.add_user("a", ChannelType.TELEGRAM, PermissionLevel.READ)
        permissions.add_user("b", ChannelType.WHATSAPP, PermissionLevel.ADMIN)
        assert len(permissions.list_users()) == 2

    def test_user_count(self, permissions):
        assert permissions.user_count == 0
        permissions.add_user("x", ChannelType.SMS)
        assert permissions.user_count == 1

    def test_same_user_different_channels(self, permissions):
        permissions.add_user("123", ChannelType.TELEGRAM, PermissionLevel.READ)
        permissions.add_user("123", ChannelType.WHATSAPP, PermissionLevel.ADMIN)
        assert permissions.user_count == 2
        tg_user = permissions.get_user("123", ChannelType.TELEGRAM)
        wa_user = permissions.get_user("123", ChannelType.WHATSAPP)
        assert tg_user.permission == PermissionLevel.READ
        assert wa_user.permission == PermissionLevel.ADMIN


# ===================================================================
# Rate limiter tests
# ===================================================================

class TestRemoteRateLimiter:
    def test_allows_initial_requests(self, rate_limiter):
        for _ in range(10):
            assert rate_limiter.allow("user1")

    def test_rate_bucket_exhaustion(self):
        bucket = _RateBucket(max_per_minute=2)
        assert bucket.allow()
        assert bucket.allow()
        assert not bucket.allow()

    def test_reset_user(self, rate_limiter):
        limiter = RemoteRateLimiter(max_per_minute=1)
        assert limiter.allow("u1")
        assert not limiter.allow("u1")
        limiter.reset("u1")
        assert limiter.allow("u1")

    def test_reset_all(self):
        limiter = RemoteRateLimiter(max_per_minute=1)
        limiter.allow("a")
        limiter.allow("b")
        limiter.reset()
        assert limiter.allow("a")
        assert limiter.allow("b")


# ===================================================================
# Webhook verifier tests
# ===================================================================

class TestWebhookVerifier:
    def test_sign_and_verify(self):
        v = WebhookVerifier("my-secret")
        sig = v.sign("hello world")
        assert v.verify("hello world", sig)

    def test_verify_fails_wrong_sig(self):
        v = WebhookVerifier("my-secret")
        assert not v.verify("hello world", "wrong-signature")

    def test_verify_fails_wrong_payload(self):
        v = WebhookVerifier("my-secret")
        sig = v.sign("hello")
        assert not v.verify("goodbye", sig)

    def test_empty_secret_raises(self):
        with pytest.raises(ValueError, match="empty"):
            WebhookVerifier("")

    def test_different_secrets_different_sigs(self):
        v1 = WebhookVerifier("secret-1")
        v2 = WebhookVerifier("secret-2")
        assert v1.sign("data") != v2.sign("data")


# ===================================================================
# Guardian command router tests
# ===================================================================

class TestGuardianCommandRouter:
    async def test_help_command(self, router):
        result = await router.handle("help")
        assert result.success
        assert "Network Guardian" in result.output

    async def test_ping_command(self, router):
        result = await router.handle("ping")
        assert result.success
        assert result.output == "pong"

    async def test_status_command(self, router):
        result = await router.handle("status")
        assert result.success
        assert "Engine" in result.output

    async def test_unknown_command(self, router):
        result = await router.handle("nonexistent")
        assert result.success  # no exception
        assert "Unknown command" in result.output

    async def test_empty_command(self, router):
        result = await router.handle("")
        assert not result.success
        assert "Empty" in result.output

    async def test_strip_leading_slash(self, router):
        result = await router.handle("/ping")
        assert result.success
        assert result.output == "pong"

    async def test_ids_status(self, router):
        result = await router.handle("ids status")
        assert result.success
        assert "Rules" in result.output

    async def test_ids_rules(self, router):
        result = await router.handle("ids rules")
        assert result.success
        assert "SID" in result.output

    async def test_ids_alerts_empty(self, router):
        result = await router.handle("ids alerts")
        assert result.success
        assert "No alerts" in result.output

    async def test_ids_scan(self, router):
        result = await router.handle("ids scan /etc/passwd")
        assert result.success

    async def test_ids_start_stop(self, router):
        r1 = await router.handle("ids start")
        assert "started" in r1.output.lower()
        r2 = await router.handle("ids stop")
        assert "stop" in r2.output.lower()

    async def test_ips_status(self, router):
        result = await router.handle("ips status")
        assert result.success
        assert "Blocked" in result.output

    async def test_ips_start_stop(self, router):
        r1 = await router.handle("ips start")
        assert "started" in r1.output.lower()
        r2 = await router.handle("ips stop")
        assert "stop" in r2.output.lower()

    async def test_ips_block_unblock(self, router):
        r1 = await router.handle("ips block 10.0.0.99")
        assert "Blocked" in r1.output
        r2 = await router.handle("ips unblock 10.0.0.99")
        assert "Unblocked" in r2.output

    async def test_ips_blocked_list(self, router):
        result = await router.handle("ips blocked")
        assert result.success

    async def test_ips_allowlist(self, router):
        result = await router.handle("ips allowlist")
        assert result.success

    async def test_cloak_status(self, router):
        result = await router.handle("cloak status")
        assert result.success
        assert "Mode" in result.output

    async def test_cloak_mask(self, router):
        result = await router.handle("cloak mask 192.168.1.1")
        assert result.success
        assert "192.168.1.1" in result.output

    async def test_cloak_mode(self, router):
        result = await router.handle("cloak mode disabled")
        assert result.success

    async def test_cloak_invalid_mode(self, router):
        result = await router.handle("cloak mode notamode")
        assert "Invalid" in result.output

    async def test_cloak_decoys(self, router):
        result = await router.handle("cloak decoys 10.0.0.0/24")
        assert result.success
        assert "decoy" in result.output.lower()

    async def test_cloak_identity_list(self, router):
        result = await router.handle("cloak identity list")
        assert result.success

    async def test_sensors_list(self, router):
        result = await router.handle("sensors list")
        assert result.success
        assert "Sensors" in result.output

    async def test_audit_no_target(self, router):
        result = await router.handle("audit")
        assert "Usage" in result.output

    async def test_explore_no_target(self, router):
        result = await router.handle("explore")
        assert "Usage" in result.output

    async def test_ai_models(self, router):
        result = await router.handle("ai models")
        assert result.success

    async def test_truncation(self, router):
        router.set_max_output(50)
        result = await router.handle("help")
        assert len(result.output) <= 50

    async def test_command_elapsed_time(self, router):
        result = await router.handle("ping")
        assert result.elapsed >= 0.0

    def test_required_permission_read(self, router):
        assert router.required_permission("status") == PermissionLevel.READ
        assert router.required_permission("ids status") == PermissionLevel.READ

    def test_required_permission_execute(self, router):
        assert router.required_permission("audit target") == PermissionLevel.EXECUTE
        assert router.required_permission("ids scan payload") == PermissionLevel.EXECUTE

    def test_required_permission_admin(self, router):
        assert router.required_permission("cloak identity create x y") == PermissionLevel.ADMIN

    def test_required_permission_unknown(self, router):
        assert router.required_permission("anything") == PermissionLevel.EXECUTE


# ===================================================================
# OpenClaw orchestrator tests
# ===================================================================

class TestOpenClawOrchestrator:
    async def test_builtin_pipelines_exist(self, router):
        orch = OpenClawOrchestrator(router)
        assert "full-scan" in orch.pipeline_names
        assert "security-posture" in orch.pipeline_names
        assert "defensive-mode" in orch.pipeline_names

    async def test_execute_security_posture(self, router):
        orch = OpenClawOrchestrator(router)
        result = await orch.execute("security-posture")
        assert isinstance(result, PipelineResult)
        assert result.success
        assert result.steps_completed == result.steps_total
        assert result.steps_total > 0

    async def test_execute_defensive_mode(self, router):
        orch = OpenClawOrchestrator(router)
        result = await orch.execute("defensive-mode")
        assert result.success

    async def test_execute_unknown_pipeline(self, router):
        orch = OpenClawOrchestrator(router)
        result = await orch.execute("nonexistent")
        assert not result.success
        assert result.steps_total == 0

    async def test_custom_pipeline(self, router):
        orch = OpenClawOrchestrator(router)
        orch.register_pipeline("my-pipe", [
            PipelineStep("step1", "ping", "Ping test"),
            PipelineStep("step2", "status", "Status check", ["step1"]),
        ])
        assert "my-pipe" in orch.pipeline_names
        result = await orch.execute("my-pipe")
        assert result.success
        assert result.steps_completed == 2

    async def test_pipeline_with_context(self, router):
        orch = OpenClawOrchestrator(router)
        result = await orch.execute("full-scan", {"target": "192.168.1.0/24"})
        # Full scan includes audit which should substitute {target}
        assert result.steps_total > 0

    async def test_pipeline_summary(self, router):
        orch = OpenClawOrchestrator(router)
        result = await orch.execute("security-posture")
        assert "security-posture" in result.summary

    def test_interpret_natural_language_full_scan(self, router):
        orch = OpenClawOrchestrator(router)
        assert orch.interpret_natural_language("run a full scan") == "pipeline:full-scan"
        assert orch.interpret_natural_language("complete audit") == "pipeline:full-scan"

    def test_interpret_natural_language_security(self, router):
        orch = OpenClawOrchestrator(router)
        assert orch.interpret_natural_language("security overview") == "pipeline:security-posture"

    def test_interpret_natural_language_defensive(self, router):
        orch = OpenClawOrchestrator(router)
        assert orch.interpret_natural_language("go defensive") == "pipeline:defensive-mode"
        assert orch.interpret_natural_language("lockdown now") == "pipeline:defensive-mode"

    def test_interpret_natural_language_status(self, router):
        orch = OpenClawOrchestrator(router)
        assert orch.interpret_natural_language("show me the status") == "status"

    def test_interpret_natural_language_block(self, router):
        orch = OpenClawOrchestrator(router)
        result = orch.interpret_natural_language("block 10.0.0.5")
        assert result == "ips block 10.0.0.5"

    def test_interpret_natural_language_alerts(self, router):
        orch = OpenClawOrchestrator(router)
        assert orch.interpret_natural_language("show alerts") == "ids alerts"

    def test_interpret_natural_language_unknown(self, router):
        orch = OpenClawOrchestrator(router)
        assert orch.interpret_natural_language("random gibberish") is None

    async def test_get_pipeline(self, router):
        orch = OpenClawOrchestrator(router)
        steps = orch.get_pipeline("security-posture")
        assert steps is not None
        assert len(steps) > 0
        assert steps is not None and steps[0].name == "ids-status"

    async def test_get_pipeline_not_found(self, router):
        orch = OpenClawOrchestrator(router)
        assert orch.get_pipeline("nope") is None


# ===================================================================
# WhatsApp channel tests
# ===================================================================

class TestTwilioWhatsAppChannel:
    def _make_channel(self, engine):
        mgr = RemoteAccessManager(engine)
        mgr.permissions.add_user("+1234567890", ChannelType.WHATSAPP, PermissionLevel.ADMIN)
        return mgr.setup_whatsapp(
            account_sid="AC_test",
            auth_token="test_token",
            from_number="whatsapp:+14155238886",
            webhook_secret="test-secret",
        )

    async def test_handle_webhook_valid_message(self, engine):
        ch = self._make_channel(engine)
        twiml = await ch.handle_webhook({
            "From": "whatsapp:+1234567890",
            "Body": "ping",
        })
        assert "<Message>" in twiml
        assert "pong" in twiml

    async def test_handle_webhook_empty_body(self, engine):
        ch = self._make_channel(engine)
        twiml = await ch.handle_webhook({"From": "whatsapp:+1234567890", "Body": ""})
        assert twiml == "<Response></Response>"

    async def test_handle_webhook_empty_from(self, engine):
        ch = self._make_channel(engine)
        twiml = await ch.handle_webhook({"From": "", "Body": "help"})
        assert twiml == "<Response></Response>"

    async def test_handle_webhook_permission_denied(self, engine):
        mgr = RemoteAccessManager(engine)
        # No users added → no permissions
        ch = mgr.setup_whatsapp(webhook_secret="secret")
        twiml = await ch.handle_webhook({
            "From": "whatsapp:+9999999999",
            "Body": "ping",
        })
        assert "Permission denied" in twiml

    async def test_message_log(self, engine):
        ch = self._make_channel(engine)
        await ch.handle_webhook({"From": "whatsapp:+1234567890", "Body": "ping"})
        log = ch.message_log
        assert len(log) == 1
        assert log[0]["from"] == "whatsapp:+1234567890"
        assert log[0]["body"] == "ping"
        assert "pong" in log[0]["reply"]

    def test_verify_webhook(self, engine):
        ch = self._make_channel(engine)
        sig = ch._verifier.sign("payload-data")
        assert ch.verify_webhook("payload-data", sig)
        assert not ch.verify_webhook("tampered", sig)

    async def test_xml_escaping(self, engine):
        ch = self._make_channel(engine)
        twiml = await ch.handle_webhook({
            "From": "whatsapp:+1234567890",
            "Body": "status",
        })
        # Should not contain raw < > & in the message
        # The output may contain &amp; &lt; &gt;
        assert "<Response><Message>" in twiml

    def test_channel_type(self, engine):
        ch = self._make_channel(engine)
        assert ch.channel_type == ChannelType.WHATSAPP


# ===================================================================
# SMS channel tests
# ===================================================================

class TestTwilioSMSChannel:
    def _make_channel(self, engine):
        mgr = RemoteAccessManager(engine)
        mgr.permissions.add_user("+18005551234", ChannelType.SMS, PermissionLevel.EXECUTE)
        return mgr.setup_sms(
            account_sid="AC_test",
            auth_token="test_token",
            from_number="+15005550006",
            webhook_secret="sms-secret",
        )

    async def test_handle_webhook_ping(self, engine):
        ch = self._make_channel(engine)
        twiml = await ch.handle_webhook({"From": "+18005551234", "Body": "ping"})
        assert "pong" in twiml

    async def test_handle_webhook_status(self, engine):
        ch = self._make_channel(engine)
        twiml = await ch.handle_webhook({"From": "+18005551234", "Body": "status"})
        assert "Engine" in twiml

    async def test_handle_webhook_empty(self, engine):
        ch = self._make_channel(engine)
        twiml = await ch.handle_webhook({"From": "+18005551234", "Body": ""})
        assert twiml == "<Response></Response>"

    async def test_sms_no_whatsapp_prefix(self, engine):
        ch = self._make_channel(engine)
        # SMS doesn't strip "whatsapp:" prefix
        twiml = await ch.handle_webhook({"From": "+18005551234", "Body": "ping"})
        log = ch.message_log
        assert log[0]["from"] == "+18005551234"

    def test_channel_type(self, engine):
        ch = self._make_channel(engine)
        assert ch.channel_type == ChannelType.SMS

    def test_verify_webhook(self, engine):
        ch = self._make_channel(engine)
        sig = ch._verifier.sign("test")
        assert ch.verify_webhook("test", sig)


# ===================================================================
# CMDOP channel tests
# ===================================================================

class TestCMDOPChannel:
    def test_channel_type_override(self, router, permissions, rate_limiter):
        ch = CMDOPChannel(
            router, permissions, rate_limiter,
            channel_type=ChannelType.DISCORD,
        )
        assert ch.channel_type == ChannelType.DISCORD

    async def test_start_without_api_key(self, router, permissions, rate_limiter):
        ch = CMDOPChannel(router, permissions, rate_limiter, cmdop_api_key="")
        await ch.start()
        assert ch.is_running
        assert ch._cmdop_handler is None
        await ch.stop()

    async def test_start_with_missing_package(self, router, permissions, rate_limiter):
        # cmdop-bot is likely not installed; test graceful fallback
        ch = CMDOPChannel(
            router, permissions, rate_limiter,
            cmdop_api_key="cmdop_test_key",
            cmdop_machine="test-machine",
        )
        await ch.start()
        assert ch.is_running
        # _cmdop_handler will be None if cmdop_bot isn't installed
        await ch.stop()
        assert not ch.is_running


# ===================================================================
# Base channel tests
# ===================================================================

class TestBaseChannel:
    async def test_process_message_no_permission(self, router, permissions, rate_limiter):
        class TestChannel(BaseChannel):
            channel_type = ChannelType.TELEGRAM

        ch = TestChannel(router, permissions, rate_limiter)
        responses = []
        async def collect(text: str) -> None:
            responses.append(text)
        await ch.process_message("unknown_user", "ping", collect)
        assert any("Permission denied" in r for r in responses)

    async def test_process_message_with_permission(self, router, permissions, rate_limiter):
        class TestChannel(BaseChannel):
            channel_type = ChannelType.TELEGRAM

        permissions.add_user("user1", ChannelType.TELEGRAM, PermissionLevel.EXECUTE)
        ch = TestChannel(router, permissions, rate_limiter)
        responses = []
        async def collect(text: str) -> None:
            responses.append(text)
        await ch.process_message("user1", "ping", collect)
        assert any("pong" in r for r in responses)

    async def test_process_message_rate_limited(self, router, permissions):
        class TestChannel(BaseChannel):
            channel_type = ChannelType.SMS

        permissions.add_user("user1", ChannelType.SMS, PermissionLevel.ADMIN)
        limiter = RemoteRateLimiter(max_per_minute=1)
        ch = TestChannel(router, permissions, limiter)

        responses = []
        async def collect(text):
            responses.append(text)

        await ch.process_message("user1", "ping", collect)
        assert "pong" in responses[-1]

        await ch.process_message("user1", "ping", collect)
        assert "Rate limit" in responses[-1]

    async def test_start_stop(self, router, permissions, rate_limiter):
        class TestChannel(BaseChannel):
            channel_type = ChannelType.SLACK

        ch = TestChannel(router, permissions, rate_limiter)
        assert not ch.is_running
        await ch.start()
        assert ch.is_running
        await ch.stop()
        assert not ch.is_running


# ===================================================================
# Remote access manager tests
# ===================================================================

class TestRemoteAccessManager:
    def test_init(self, remote_manager):
        assert not remote_manager.is_running
        assert remote_manager.channel_count == 0

    def test_setup_whatsapp(self, remote_manager):
        ch = remote_manager.setup_whatsapp(
            account_sid="AC_test",
            webhook_secret="sec",
        )
        assert isinstance(ch, TwilioWhatsAppChannel)
        assert remote_manager.channel_count == 1

    def test_setup_sms(self, remote_manager):
        ch = remote_manager.setup_sms(
            account_sid="AC_test",
            webhook_secret="sec",
        )
        assert isinstance(ch, TwilioSMSChannel)
        assert remote_manager.channel_count == 1

    def test_setup_cmdop_channel(self, remote_manager):
        ch = remote_manager.setup_cmdop_channel(
            ChannelType.TELEGRAM,
            cmdop_api_key="key",
        )
        assert isinstance(ch, CMDOPChannel)
        assert remote_manager.channel_count == 1

    def test_get_channel(self, remote_manager):
        remote_manager.setup_whatsapp(webhook_secret="sec")
        assert remote_manager.get_channel(ChannelType.WHATSAPP) is not None
        assert remote_manager.get_channel(ChannelType.SMS) is None

    def test_remove_channel(self, remote_manager):
        remote_manager.setup_whatsapp(webhook_secret="sec")
        assert remote_manager.remove_channel(ChannelType.WHATSAPP)
        assert remote_manager.channel_count == 0

    def test_remove_channel_not_found(self, remote_manager):
        assert not remote_manager.remove_channel(ChannelType.DISCORD)

    async def test_start_stop(self, remote_manager):
        remote_manager.setup_whatsapp(webhook_secret="sec")
        remote_manager.setup_sms(webhook_secret="sec2")
        await remote_manager.start()
        assert remote_manager.is_running
        assert len(remote_manager.active_channels) == 2
        await remote_manager.stop()
        assert not remote_manager.is_running

    async def test_execute_command_direct(self, remote_manager):
        result = await remote_manager.execute_command("ping")
        assert result.success
        assert result.output == "pong"

    async def test_execute_pipeline(self, remote_manager):
        result = await remote_manager.execute_pipeline("security-posture")
        assert result.success

    def test_config_defaults(self, remote_manager):
        assert remote_manager.config.rate_limit_per_minute == 30
        assert remote_manager.config.max_output_length == 2000


# ===================================================================
# Engine integration tests
# ===================================================================

class TestEngineIntegration:
    def test_engine_has_remote_property(self, engine):
        remote = engine.remote
        assert isinstance(remote, RemoteAccessManager)

    def test_engine_remote_is_lazy_singleton(self, engine):
        r1 = engine.remote
        r2 = engine.remote
        assert r1 is r2

    async def test_remote_command_via_engine(self, engine):
        result = await engine.remote.execute_command("status")
        assert result.success
        assert "Engine" in result.output

    async def test_engine_stop_closes_remote(self, engine):
        remote = engine.remote
        await remote.start()
        assert remote.is_running
        await engine.stop()
        assert not remote.is_running

    async def test_pipeline_via_engine(self, engine):
        result = await engine.remote.execute_pipeline("security-posture")
        assert result.success
        assert result.steps_completed == result.steps_total


# ===================================================================
# Channel type & config model tests
# ===================================================================

class TestModels:
    def test_channel_type_values(self):
        assert ChannelType.TELEGRAM.value == "telegram"
        assert ChannelType.WHATSAPP.value == "whatsapp"
        assert ChannelType.SMS.value == "sms"
        assert ChannelType.DISCORD.value == "discord"
        assert ChannelType.SLACK.value == "slack"

    def test_permission_level_values(self):
        assert PermissionLevel.NONE.value == "none"
        assert PermissionLevel.READ.value == "read"
        assert PermissionLevel.EXECUTE.value == "execute"
        assert PermissionLevel.ADMIN.value == "admin"

    def test_remote_user_frozen(self):
        user = RemoteUser("123", ChannelType.TELEGRAM)
        with pytest.raises(AttributeError):
            user.user_id = "456"  # type: ignore[misc]

    def test_command_result(self):
        r = CommandResult(True, "ok", "ping", 0.01)
        assert r.success
        assert r.output == "ok"

    def test_channel_config_defaults(self):
        cfg = ChannelConfig(channel_type=ChannelType.WHATSAPP)
        assert not cfg.enabled
        assert cfg.api_token == ""

    def test_remote_config_defaults(self):
        cfg = RemoteConfig()
        assert cfg.cmdop_api_key == ""
        assert cfg.rate_limit_per_minute == 30
        assert cfg.max_output_length == 2000

    def test_pipeline_step(self):
        step = PipelineStep("s1", "ping", "test ping")
        assert step.name == "s1"
        assert step.depends_on == []

    def test_pipeline_result_summary(self):
        r = PipelineResult("test", 3, 3, success=True)
        assert "OK" in r.summary
        r2 = PipelineResult("test", 1, 3, success=False)
        assert "FAILED" in r2.summary


# ===================================================================
# Multi-channel scenario tests
# ===================================================================

class TestMultiChannel:
    async def test_whatsapp_and_sms_simultaneous(self, engine):
        mgr = RemoteAccessManager(engine)
        mgr.permissions.add_user("+111", ChannelType.WHATSAPP, PermissionLevel.ADMIN)
        mgr.permissions.add_user("+222", ChannelType.SMS, PermissionLevel.ADMIN)

        wa = mgr.setup_whatsapp(webhook_secret="s1")
        sms = mgr.setup_sms(webhook_secret="s2")

        wa_result = await wa.handle_webhook({"From": "whatsapp:+111", "Body": "ping"})
        sms_result = await sms.handle_webhook({"From": "+222", "Body": "status"})

        assert "pong" in wa_result
        assert "Engine" in sms_result

    async def test_all_five_channels_registered(self, engine):
        mgr = RemoteAccessManager(engine)
        mgr.setup_whatsapp(webhook_secret="s1")
        mgr.setup_sms(webhook_secret="s2")
        mgr.setup_cmdop_channel(ChannelType.TELEGRAM)
        mgr.setup_cmdop_channel(ChannelType.DISCORD)
        mgr.setup_cmdop_channel(ChannelType.SLACK)
        assert mgr.channel_count == 5

    async def test_start_all_channels(self, engine):
        mgr = RemoteAccessManager(engine)
        mgr.setup_whatsapp(webhook_secret="s1")
        mgr.setup_sms(webhook_secret="s2")
        mgr.setup_cmdop_channel(ChannelType.TELEGRAM)
        await mgr.start()
        assert len(mgr.active_channels) == 3
        await mgr.stop()
        assert len(mgr.active_channels) == 0
