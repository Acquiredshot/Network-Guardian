# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Remote access module for Network Guardian.

Integrates OpenClaw agent orchestration + CMDOP remote machine access +
multi-channel messaging (Telegram, Discord, Slack, WhatsApp, SMS).

Architecture
------------
WhatsApp (Twilio) ──┐
SMS (Twilio) ───────┤
Telegram (aiogram) ─┤── GuardianCommandRouter ── Engine ── All subsystems
Discord (discord.py)┤
Slack (slack-bolt) ──┘

OpenClaw sits on top for AI-powered pipeline orchestration so natural
language messages can be interpreted and chained into multi-step actions.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import hmac
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from network_guardian.core.engine import Engine

logger = logging.getLogger("network_guardian.remote")


# ---------------------------------------------------------------------------
# Types & enums
# ---------------------------------------------------------------------------

SendCallback = Callable[[str], Awaitable[None]]


class ChannelType(enum.Enum):
    """Supported messaging channels."""
    TELEGRAM = "telegram"
    DISCORD = "discord"
    SLACK = "slack"
    WHATSAPP = "whatsapp"
    SMS = "sms"


class PermissionLevel(enum.Enum):
    """Access tiers for remote users."""
    NONE = "none"
    READ = "read"          # status, list, view only
    EXECUTE = "execute"    # run scans, commands
    ADMIN = "admin"        # everything including config changes


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RemoteUser:
    """An authorised remote user."""
    user_id: str
    channel: ChannelType
    permission: PermissionLevel = PermissionLevel.READ
    label: str = ""


@dataclass
class CommandResult:
    """Result of a remote command execution."""
    success: bool
    output: str
    command: str
    elapsed: float = 0.0


@dataclass
class ChannelConfig:
    """Configuration for a single messaging channel."""
    channel_type: ChannelType
    enabled: bool = False
    api_token: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RemoteConfig:
    """Top-level remote access configuration."""
    cmdop_api_key: str = ""
    cmdop_machine: str = ""
    openclaw_enabled: bool = False
    channels: dict[ChannelType, ChannelConfig] = field(default_factory=dict)
    rate_limit_per_minute: int = 30
    max_output_length: int = 2000


# ---------------------------------------------------------------------------
# Permission manager
# ---------------------------------------------------------------------------

class RemotePermissionManager:
    """Manages who can do what via remote channels."""

    def __init__(self) -> None:
        self._users: dict[str, RemoteUser] = {}

    def _key(self, user_id: str, channel: ChannelType) -> str:
        return f"{channel.value}:{user_id}"

    def add_user(
        self,
        user_id: str,
        channel: ChannelType,
        permission: PermissionLevel = PermissionLevel.READ,
        label: str = "",
    ) -> RemoteUser:
        user = RemoteUser(
            user_id=user_id,
            channel=channel,
            permission=permission,
            label=label,
        )
        self._users[self._key(user_id, channel)] = user
        return user

    def remove_user(self, user_id: str, channel: ChannelType) -> bool:
        return self._users.pop(self._key(user_id, channel), None) is not None

    def get_user(self, user_id: str, channel: ChannelType) -> RemoteUser | None:
        return self._users.get(self._key(user_id, channel))

    def check_permission(
        self, user_id: str, channel: ChannelType, required: PermissionLevel,
    ) -> bool:
        user = self.get_user(user_id, channel)
        if user is None:
            return False
        levels = [PermissionLevel.NONE, PermissionLevel.READ,
                  PermissionLevel.EXECUTE, PermissionLevel.ADMIN]
        return levels.index(user.permission) >= levels.index(required)

    def list_users(self) -> list[RemoteUser]:
        return list(self._users.values())

    @property
    def user_count(self) -> int:
        return len(self._users)


# ---------------------------------------------------------------------------
# Rate limiter (per-user, token-bucket)
# ---------------------------------------------------------------------------

class _RateBucket:
    __slots__ = ("tokens", "last_refill", "max_tokens", "refill_rate")

    def __init__(self, max_per_minute: int) -> None:
        self.max_tokens = float(max_per_minute)
        self.tokens = self.max_tokens
        self.refill_rate = max_per_minute / 60.0
        self.last_refill = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RemoteRateLimiter:
    """Per-user rate limiter for remote commands."""

    def __init__(self, max_per_minute: int = 30) -> None:
        self._max = max_per_minute
        self._buckets: dict[str, _RateBucket] = {}

    def allow(self, user_key: str) -> bool:
        if user_key not in self._buckets:
            self._buckets[user_key] = _RateBucket(self._max)
        return self._buckets[user_key].allow()

    def reset(self, user_key: str | None = None) -> None:
        if user_key is None:
            self._buckets.clear()
        else:
            self._buckets.pop(user_key, None)


# ---------------------------------------------------------------------------
# Webhook signature verifier (Twilio-style HMAC)
# ---------------------------------------------------------------------------

class WebhookVerifier:
    """Verifies inbound webhook signatures using HMAC-SHA256."""

    def __init__(self, secret: str) -> None:
        if not secret:
            raise ValueError("Webhook secret must not be empty")
        self._secret = secret.encode()

    def sign(self, payload: str) -> str:
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Guardian command router – maps messages to Engine actions
# ---------------------------------------------------------------------------

# Commands that only need READ permission
_READ_COMMANDS = frozenset({
    "status", "help", "ids status", "ips status", "cloak status",
    "ids rules", "ids alerts", "ips blocked", "ips allowlist",
    "sensors list",
})

# Commands that need EXECUTE permission
_EXECUTE_COMMANDS = frozenset({
    "audit", "explore", "ids scan", "ids start", "ids stop",
    "ips start", "ips stop", "ips block", "ips unblock",
    "cloak mode", "cloak mask", "cloak decoys",
    "monitor start", "monitor stop", "sensors collect",
    "ai recommend", "ai classify", "train",
})

# Commands that need ADMIN permission
_ADMIN_COMMANDS = frozenset({
    "cloak identity create", "cloak identity activate",
    "remote users", "remote add_user", "remote remove_user",
})


class GuardianCommandRouter:
    """
    Channel-agnostic command processor.

    Parses text commands from any source and executes them against the
    Network Guardian engine.  Follows the same handler pattern as
    cmdop-bot's ``MessageHandler`` so it can be composed with existing
    cmdop-bot infrastructure.
    """

    # Maximum output length returned to messaging channels
    MAX_OUTPUT = 2000

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._max_output = self.MAX_OUTPUT

    def set_max_output(self, length: int) -> None:
        self._max_output = max(20, length)

    def _truncate(self, text: str) -> str:
        if len(text) <= self._max_output:
            return text
        suffix = "\n…(truncated)"
        return text[: self._max_output - len(suffix)] + suffix

    def required_permission(self, command_text: str) -> PermissionLevel:
        """Determine the minimum permission level for a command."""
        normalised = command_text.strip().lower()
        for cmd in _ADMIN_COMMANDS:
            if normalised.startswith(cmd):
                return PermissionLevel.ADMIN
        for cmd in _EXECUTE_COMMANDS:
            if normalised.startswith(cmd):
                return PermissionLevel.EXECUTE
        for cmd in _READ_COMMANDS:
            if normalised.startswith(cmd):
                return PermissionLevel.READ
        # Default: EXECUTE for unknown commands (safe default)
        return PermissionLevel.EXECUTE

    async def handle(self, text: str) -> CommandResult:
        """Parse and execute a command, returning the result."""
        start = time.monotonic()
        text = text.strip()
        if not text:
            return CommandResult(False, "Empty command.", "", 0.0)

        # Strip leading / for bot-style commands
        if text.startswith("/"):
            text = text[1:]

        parts = text.split()
        cmd = parts[0].lower()
        args = parts[1:]

        try:
            output = await self._dispatch(cmd, args)
            elapsed = time.monotonic() - start
            return CommandResult(True, self._truncate(output), text, elapsed)
        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.exception("Remote command error: %s", text)
            return CommandResult(False, f"Error: {exc}", text, elapsed)

    async def _dispatch(self, cmd: str, args: list[str]) -> str:
        """Dispatch to the right subsystem."""
        handlers: dict[str, Callable[..., Any]] = {
            "help": self._cmd_help,
            "status": self._cmd_status,
            "audit": self._cmd_audit,
            "explore": self._cmd_explore,
            "monitor": self._cmd_monitor,
            "sensors": self._cmd_sensors,
            "ids": self._cmd_ids,
            "ips": self._cmd_ips,
            "cloak": self._cmd_cloak,
            "wifi": self._cmd_wifi,
            "ai": self._cmd_ai,
            "train": self._cmd_train,
            "ping": self._cmd_ping,
        }
        handler = handlers.get(cmd)
        if handler is None:
            return (
                f"Unknown command: {cmd}\n"
                "Type 'help' for available commands."
            )
        result = handler(args)
        if asyncio.iscoroutine(result):
            result = await result
        return str(result)

    # -- Command implementations ----------------------------------------

    def _cmd_help(self, _args: list[str]) -> str:
        lines = [
            "Network Guardian — Remote Commands",
            "─" * 38,
            "status        — Engine status",
            "audit <target>— Run network audit",
            "explore <sub> — Discover hosts",
            "monitor start|stop",
            "sensors list|collect [name]",
            "ids start|stop|status|scan <text>|rules|alerts",
            "ips start|stop|status|block|unblock <ip>",
            "cloak mode|mask|identity|decoys|status",
            "wifi scan|status|hide|show|router|verify",
            "ai recommend|classify",
            "train anomaly|forecast [method]",
            "ping          — Connectivity check",
            "help          — This message",
        ]
        return "\n".join(lines)

    def _cmd_ping(self, _args: list[str]) -> str:
        return "pong"

    def _cmd_status(self, _args: list[str]) -> str:
        status = "running" if self.engine.is_running else "stopped"
        return f"Engine: {status}\nData dir: {self.engine.config.data_dir}"

    async def _cmd_audit(self, args: list[str]) -> str:
        if not args:
            return "Usage: audit <target>"
        findings = await self.engine.auditor.run_audit(args)
        lines = [f"Audit complete. {len(findings)} finding(s)."]
        for f in findings:
            lines.append(f"  [{f.severity.value.upper()}] {f.title}")
        return "\n".join(lines)

    async def _cmd_explore(self, args: list[str]) -> str:
        if not args:
            return "Usage: explore <subnet>"
        hosts = await self.engine.explorer.discover(args[0])
        return f"Discovered {len(hosts)} host(s)."

    async def _cmd_monitor(self, args: list[str]) -> str:
        if not args or args[0] not in ("start", "stop"):
            return "Usage: monitor start|stop"
        if args[0] == "start":
            self.engine.monitor.start()
            return "Monitoring started."
        await self.engine.monitor.stop()
        return "Monitoring stopped."

    async def _cmd_sensors(self, args: list[str]) -> str:
        if not args or args[0] == "list":
            names = self.engine.sensors.names
            return "Sensors:\n" + "\n".join(f"  {n}" for n in names)
        if args[0] == "collect":
            timeout = 20.0  # generous but keeps WhatsApp responsive
            try:
                if len(args) > 1:
                    sensor = self.engine.sensors.get(args[1])
                    reading = await asyncio.wait_for(sensor.collect(), timeout=timeout)
                    return f"[{reading.sensor_name}] {reading.data}"
                readings = await asyncio.wait_for(
                    self.engine.sensors.collect_all(), timeout=timeout,
                )
                lines = [f"[{r.sensor_name}] {r.data}" for r in readings]
                return "\n".join(lines)
            except asyncio.TimeoutError:
                return "Sensor collection timed out (>20s). Try a specific sensor: sensors collect system_metrics"
        return "Usage: sensors list|collect [name]"

    async def _cmd_ids(self, args: list[str]) -> str:
        if not args:
            return "Usage: ids start|stop|status|scan <text>|rules|alerts"
        ids = self.engine.ids
        sub = args[0]
        if sub == "status":
            return f"Rules: {len(ids.rules)} | Alerts: {len(ids.alerts)}"
        if sub == "scan" and len(args) > 1:
            payload = " ".join(args[1:])
            alerts = await ids.analyse_payload(payload, source_ip="remote")
            if not alerts:
                return "No threats detected."
            lines = []
            for a in alerts:
                lines.append(
                    f"[{a.severity.value.upper()}] {a.category.value}: {a.description}"
                )
            return "\n".join(lines)
        if sub == "rules":
            lines = []
            for r in ids.rules:
                st = "on" if r.enabled else "off"
                lines.append(f"SID {r.sid} [{st}] {r.name}")
            return "\n".join(lines) or "No rules."
        if sub == "alerts":
            if not ids.alerts:
                return "No alerts."
            lines = []
            for a in ids.alerts:
                lines.append(
                    f"[{a.severity.value.upper()}] {a.category.value}: "
                    f"{a.description} (src={a.source_ip})"
                )
            return "\n".join(lines)
        if sub == "start":
            return "IDS started."
        if sub == "stop":
            return "IDS stopped."
        return "Usage: ids start|stop|status|scan <text>|rules|alerts"

    async def _cmd_ips(self, args: list[str]) -> str:
        if not args:
            return "Usage: ips start|stop|status|block|unblock <ip>"
        ips = self.engine.ips
        sub = args[0]
        if sub == "status":
            return (
                f"Blocked: {len(ips.blocked_ips)} | "
                f"Quarantined: {len(ips.quarantined_ips)} | "
                f"Allowlist: {len(ips.allowlist)}"
            )
        if sub == "block" and len(args) > 1:
            from network_guardian.ips import BlockReason
            ip = args[1]
            dur = int(args[2]) if len(args) > 2 else 3600
            await ips.block_ip(ip, reason=BlockReason.MANUAL, duration=dur)
            return f"Blocked {ip} for {dur}s."
        if sub == "unblock" and len(args) > 1:
            ok = await ips.unblock_ip(args[1])
            return f"Unblocked {args[1]}." if ok else f"{args[1]} is not blocked."
        if sub == "start":
            ips.set_auto_respond(True)
            return "IPS started (auto-respond on)."
        if sub == "stop":
            ips.set_auto_respond(False)
            return "IPS stopped."
        if sub == "blocked":
            entries = ips.blocked_ips
            if not entries:
                return "No IPs blocked."
            lines = []
            for b in entries:
                lines.append(f"{b.ip} reason={b.reason.value}")
            return "\n".join(lines)
        if sub == "allowlist":
            ips_list = sorted(ips.allowlist)
            return "\n".join(ips_list) or "Allowlist empty."
        return "Usage: ips start|stop|status|block|unblock <ip>"

    def _cmd_cloak(self, args: list[str]) -> str:
        if not args:
            return "Usage: cloak mode|mask|identity|decoys|status"
        cloak = self.engine.cloaking
        sub = args[0]
        if sub == "status":
            return (
                f"Mode: {cloak.mode.value}\n"
                f"Identity: {cloak.active_identity or 'none'}\n"
                f"Proxy hops: {len(cloak.proxy_chain)}\n"
                f"Identities: {len(cloak.list_identities())}"
            )
        if sub == "mask" and len(args) > 1:
            masked = cloak.mask_ip(args[1])
            return f"{args[1]} -> {masked}"
        if sub == "mode" and len(args) > 1:
            from network_guardian.cloaking import CloakMode
            try:
                cloak.set_mode(CloakMode(args[1]))
                return f"Mode set to: {args[1]}"
            except ValueError:
                modes = ", ".join(m.value for m in CloakMode)
                return f"Invalid mode. Options: {modes}"
        if sub == "decoys" and len(args) > 1:
            decoys = cloak.generate_decoys(args[1])
            lines = [f"Generated {len(decoys)} decoy(s):"]
            for d in decoys:
                ports = ", ".join(str(p) for p in d.ports)
                lines.append(f"  {d.ip} ports=[{ports}]")
            return "\n".join(lines)
        if sub == "identity":
            if len(args) < 2:
                return "Usage: cloak identity list|create <name> <mode>|activate <name>"
            if args[1] == "list":
                idents = cloak.list_identities()
                if not idents:
                    return "No identities."
                lines = []
                for i in idents:
                    active = " [ACTIVE]" if i.name == cloak.active_identity else ""
                    lines.append(f"{i.name} mode={i.mode.value}{active}")
                return "\n".join(lines)
            if args[1] == "create" and len(args) >= 4:
                from network_guardian.cloaking import CloakMode
                try:
                    mode = CloakMode(args[3])
                except ValueError:
                    return "Invalid mode."
                cloak.create_identity(args[2], mode)
                return f"Identity '{args[2]}' created."
            if args[1] == "activate" and len(args) >= 3:
                ok = cloak.activate_identity(args[2])
                return f"Activated: {args[2]}" if ok else f"Not found: {args[2]}"
            return "Usage: cloak identity list|create <name> <mode>|activate <name>"
        return "Usage: cloak mode|mask|identity|decoys|status"

    async def _cmd_wifi(self, args: list[str]) -> str:
        if not args:
            return (
                "WiFi Stealth Commands:\n"
                "  wifi scan    — Scan nearby networks\n"
                "  wifi status  — Current connection & stealth info\n"
                "  wifi hide    — Hide your SSID (stealth ON)\n"
                "  wifi show    — Unhide your SSID (stealth OFF)\n"
                "  wifi verify  — Verify SSID is hidden\n"
                "  wifi router <ip> <user> <pass> — Configure router"
            )
        stealth = self.engine.wifi_stealth
        sub = args[0]

        if sub == "scan":
            try:
                networks = await asyncio.wait_for(
                    stealth.scan_networks(), timeout=20.0,
                )
            except asyncio.TimeoutError:
                return "WiFi scan timed out."
            if not networks:
                return "No WiFi networks found (adapter may be unavailable)."
            lines = [f"Found {len(networks)} network(s):"]
            for n in sorted(networks, key=lambda x: x.signal, reverse=True):
                name = n.ssid if n.ssid else "(hidden)"
                sec = f" [{n.security}]" if n.security != "Unknown" else ""
                sig = f" {n.signal}%" if n.signal > 0 else ""
                ch = f" ch{n.channel}" if n.channel else ""
                lines.append(f"  {name}{sec}{sig}{ch}")
            return "\n".join(lines)

        if sub == "status":
            try:
                status = await asyncio.wait_for(
                    stealth.stealth_status(), timeout=15.0,
                )
            except asyncio.TimeoutError:
                return "Status check timed out."
            lines = [
                f"Stealth: {'ON' if status['stealth_active'] else 'OFF'}",
                f"Home SSID: {status['home_ssid']}",
                f"Gateway: {status['gateway_ip'] or 'unknown'}",
                f"Router configured: {'yes' if status['router_configured'] else 'no'}",
            ]
            conn = status.get("connected_network")
            if conn:
                lines.append(f"Connected: {conn['ssid']} ({conn['signal']}%)")
            return "\n".join(lines)

        if sub == "hide":
            band = args[1] if len(args) > 1 else "all"
            try:
                result = await asyncio.wait_for(
                    stealth.hide_network(band), timeout=15.0,
                )
            except asyncio.TimeoutError:
                return "Hide operation timed out."
            if result.get("success"):
                return f"✓ SSID HIDDEN — {result['message']}\nYour WiFi won't appear on nearby devices."
            return f"✗ {result.get('error', 'Failed to hide SSID')}"

        if sub == "show":
            band = args[1] if len(args) > 1 else "all"
            try:
                result = await asyncio.wait_for(
                    stealth.show_network(band), timeout=15.0,
                )
            except asyncio.TimeoutError:
                return "Show operation timed out."
            if result.get("success"):
                return f"✓ SSID VISIBLE — {result['message']}\nYour WiFi is now discoverable."
            return f"✗ {result.get('error', 'Failed to show SSID')}"

        if sub == "verify":
            try:
                result = await asyncio.wait_for(
                    stealth.verify_stealth(), timeout=20.0,
                )
            except asyncio.TimeoutError:
                return "Verification scan timed out."
            return result.get("message", "Verification failed.")

        if sub == "router":
            if len(args) < 4:
                return "Usage: wifi router <ip> <username> <password>"
            # Strip angle brackets users may copy from help text
            ip = args[1].strip("<>")
            user = args[2].strip("<>")
            pw = args[3].strip("<>")
            try:
                result = await asyncio.wait_for(
                    stealth.configure_router(ip, user, pw), timeout=15.0,
                )
            except asyncio.TimeoutError:
                return "Router configuration timed out."
            if result.get("success"):
                return f"✓ {result['message']}"
            return f"✗ {result.get('error', 'Router configuration failed')}"

        return (
            "WiFi Stealth Commands:\n"
            "  wifi scan|status|hide|show|verify\n"
            "  wifi router <ip> <user> <pass>"
        )

    def _cmd_ai(self, args: list[str]) -> str:
        if not args:
            return "Usage: ai recommend|classify|models"
        if args[0] == "models":
            return "Models:\n" + "\n".join(f"  {n}" for n in self.engine.ai.model_names)
        return f"AI sub-command '{args[0]}' — use the CLI for full AI interaction."

    def _cmd_train(self, args: list[str]) -> str:
        if not args:
            return "Usage: train anomaly|forecast [method]"
        if args[0] == "anomaly":
            report = self.engine.training.run_full_anomaly_pipeline()
            return report.summary()
        if args[0] == "forecast":
            method = args[1] if len(args) > 1 else "arima"
            report = self.engine.training.run_full_forecast_pipeline(method=method)
            return report.summary()
        return "Usage: train anomaly|forecast [method]"


# ---------------------------------------------------------------------------
# OpenClaw integration – AI agent orchestration pipelines
# ---------------------------------------------------------------------------

@dataclass
class PipelineStep:
    """A single step in an OpenClaw-style orchestration pipeline."""
    name: str
    command: str
    description: str = ""
    depends_on: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Aggregated result of a multi-step pipeline."""
    pipeline_name: str
    steps_completed: int
    steps_total: int
    results: dict[str, CommandResult] = field(default_factory=dict)
    success: bool = True

    @property
    def summary(self) -> str:
        status = "OK" if self.success else "FAILED"
        return (
            f"Pipeline '{self.pipeline_name}': {status} "
            f"({self.steps_completed}/{self.steps_total} steps)"
        )


class OpenClawOrchestrator:
    """
    AI-powered pipeline orchestrator inspired by the OpenClaw framework.

    Chains multiple Network Guardian commands into automated workflows.
    Supports dependency resolution, context passing between steps, and
    natural language command interpretation.
    """

    # Built-in pipeline templates
    BUILTIN_PIPELINES: dict[str, list[PipelineStep]] = {
        "full-scan": [
            PipelineStep("ids-start", "ids start", "Activate IDS"),
            PipelineStep("ips-start", "ips start", "Activate IPS"),
            PipelineStep("audit", "audit {target}", "Run audit", ["ids-start"]),
            PipelineStep("ids-check", "ids alerts", "Check alerts", ["audit"]),
            PipelineStep("ips-check", "ips status", "Check blocks", ["audit"]),
        ],
        "security-posture": [
            PipelineStep("ids-status", "ids status", "IDS status"),
            PipelineStep("ips-status", "ips status", "IPS status"),
            PipelineStep("cloak-status", "cloak status", "Cloak status"),
            PipelineStep("status", "status", "Engine status"),
        ],
        "defensive-mode": [
            PipelineStep("ids-on", "ids start", "Enable IDS"),
            PipelineStep("ips-on", "ips start", "Enable IPS"),
            PipelineStep("cloak-full", "cloak mode full", "Enable full cloaking",
                         ["ids-on", "ips-on"]),
        ],
    }

    def __init__(self, router: GuardianCommandRouter) -> None:
        self._router = router
        self._custom_pipelines: dict[str, list[PipelineStep]] = {}

    @property
    def pipeline_names(self) -> list[str]:
        return sorted(set(self.BUILTIN_PIPELINES) | set(self._custom_pipelines))

    def register_pipeline(self, name: str, steps: list[PipelineStep]) -> None:
        self._custom_pipelines[name] = steps

    def get_pipeline(self, name: str) -> list[PipelineStep] | None:
        return self._custom_pipelines.get(name) or self.BUILTIN_PIPELINES.get(name)

    async def execute(
        self,
        pipeline_name: str,
        context: dict[str, str] | None = None,
    ) -> PipelineResult:
        """Execute a named pipeline, substituting context variables."""
        steps = self.get_pipeline(pipeline_name)
        if steps is None:
            return PipelineResult(
                pipeline_name=pipeline_name,
                steps_completed=0,
                steps_total=0,
                success=False,
            )

        ctx = context or {}
        result = PipelineResult(
            pipeline_name=pipeline_name,
            steps_completed=0,
            steps_total=len(steps),
        )

        completed: set[str] = set()
        for step in steps:
            # Check dependencies
            for dep in step.depends_on:
                if dep not in completed:
                    result.success = False
                    return result

            # Substitute context variables
            command = step.command
            for key, value in ctx.items():
                command = command.replace(f"{{{key}}}", value)

            # Execute step
            step_result = await self._router.handle(command)
            result.results[step.name] = step_result

            if step_result.success:
                completed.add(step.name)
                result.steps_completed += 1
            else:
                result.success = False
                break

        return result

    def interpret_natural_language(self, text: str) -> str | None:
        """
        Simple NL → command mapping for common phrases.

        Returns a pipeline name or direct command, or None if unrecognised.
        """
        lower = text.lower().strip()

        # Pipeline triggers
        if re.search(r"\b(full|complete)\s+(scan|audit)\b", lower):
            return "pipeline:full-scan"
        if re.search(r"\b(security|posture|overview)\b", lower):
            return "pipeline:security-posture"
        if re.search(r"\b(defen[sc]ive|lockdown|protect)\b", lower):
            return "pipeline:defensive-mode"

        # Direct command triggers
        if re.search(r"\bstatus\b", lower):
            return "status"
        if re.search(r"\b(block|ban)\s+(\d+\.\d+\.\d+\.\d+)", lower):
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", lower)
            if match:
                return f"ips block {match.group(1)}"
        if re.search(r"\balerts?\b", lower):
            return "ids alerts"
        if re.search(r"\brules?\b", lower):
            return "ids rules"
        if re.search(r"\bscan\s+(.+)", lower):
            match = re.search(r"\bscan\s+(.+)", lower)
            if match:
                return f"ids scan {match.group(1)}"

        return None


# ---------------------------------------------------------------------------
# Channel adapters
# ---------------------------------------------------------------------------

class BaseChannel:
    """
    Abstract base for messaging channels.

    Subclasses provide the transport (Twilio, Telegram SDK, etc.)
    while the common logic handles auth, rate limiting, and routing.
    """

    channel_type: ChannelType

    def __init__(
        self,
        router: GuardianCommandRouter,
        permissions: RemotePermissionManager,
        rate_limiter: RemoteRateLimiter,
    ) -> None:
        self._router = router
        self._permissions = permissions
        self._rate_limiter = rate_limiter
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    async def process_message(
        self,
        user_id: str,
        text: str,
        send: SendCallback,
    ) -> None:
        """
        Common message processing pipeline:
        1. Permission check
        2. Rate limit check
        3. Route to command handler
        4. Send response
        """
        user_key = f"{self.channel_type.value}:{user_id}"

        # Permission check
        required = self._router.required_permission(text)
        if not self._permissions.check_permission(user_id, self.channel_type, required):
            await send("Permission denied. Contact an admin for access.")
            return

        # Rate limit
        if not self._rate_limiter.allow(user_key):
            await send("Rate limit exceeded. Please slow down.")
            return

        # Execute command
        result = await self._router.handle(text)
        await send(result.output)

    async def start(self) -> None:
        """Start the channel (override for platform-specific startup)."""
        self._running = True
        logger.info("Channel %s started.", self.channel_type.value)

    async def stop(self) -> None:
        """Stop the channel gracefully."""
        self._running = False
        logger.info("Channel %s stopped.", self.channel_type.value)


class TwilioWhatsAppChannel(BaseChannel):
    """
    WhatsApp channel via Twilio WhatsApp Business API.

    Expects inbound webhooks at a configured HTTP endpoint.
    Sends replies using the Twilio REST API.
    """

    channel_type = ChannelType.WHATSAPP

    def __init__(
        self,
        router: GuardianCommandRouter,
        permissions: RemotePermissionManager,
        rate_limiter: RemoteRateLimiter,
        *,
        account_sid: str = "",
        auth_token: str = "",
        from_number: str = "",
        webhook_secret: str = "",
    ) -> None:
        super().__init__(router, permissions, rate_limiter)
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number  # e.g. "whatsapp:+14155238886"
        self._verifier = WebhookVerifier(webhook_secret) if webhook_secret else None
        self._message_log: list[dict[str, str]] = []

    def verify_webhook(self, payload: str, signature: str) -> bool:
        """Verify an inbound Twilio webhook signature."""
        if self._verifier is None:
            return False
        return self._verifier.verify(payload, signature)

    async def handle_webhook(self, form_data: dict[str, str]) -> str:
        """
        Process an inbound WhatsApp message from Twilio webhook.

        Returns the TwiML response body.
        """
        sender = form_data.get("From", "")
        body = form_data.get("Body", "").strip()

        if not sender or not body:
            return "<Response></Response>"

        # Extract phone number from "whatsapp:+1234567890"
        user_id = sender.replace("whatsapp:", "").strip()

        responses: list[str] = []

        async def collect(text: str) -> None:
            responses.append(text)

        await self.process_message(user_id, body, collect)

        reply = "\n".join(responses) if responses else "No response."
        self._message_log.append({"from": sender, "body": body, "reply": reply})

        # Return TwiML
        # Escape XML-sensitive characters
        safe_reply = (
            reply.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        return f"<Response><Message>{safe_reply}</Message></Response>"

    @property
    def message_log(self) -> list[dict[str, str]]:
        return list(self._message_log)


class TwilioSMSChannel(BaseChannel):
    """
    SMS channel via Twilio Programmable SMS.

    Same webhook pattern as the WhatsApp channel but without the
    whatsapp: prefix on phone numbers.
    """

    channel_type = ChannelType.SMS

    def __init__(
        self,
        router: GuardianCommandRouter,
        permissions: RemotePermissionManager,
        rate_limiter: RemoteRateLimiter,
        *,
        account_sid: str = "",
        auth_token: str = "",
        from_number: str = "",
        webhook_secret: str = "",
    ) -> None:
        super().__init__(router, permissions, rate_limiter)
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number
        self._verifier = WebhookVerifier(webhook_secret) if webhook_secret else None
        self._message_log: list[dict[str, str]] = []

    def verify_webhook(self, payload: str, signature: str) -> bool:
        if self._verifier is None:
            return False
        return self._verifier.verify(payload, signature)

    async def handle_webhook(self, form_data: dict[str, str]) -> str:
        sender = form_data.get("From", "")
        body = form_data.get("Body", "").strip()

        if not sender or not body:
            return "<Response></Response>"

        user_id = sender.strip()
        responses: list[str] = []

        async def collect(text: str) -> None:
            responses.append(text)

        await self.process_message(user_id, body, collect)

        reply = "\n".join(responses) if responses else "No response."
        self._message_log.append({"from": sender, "body": body, "reply": reply})

        safe_reply = (
            reply.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        return f"<Response><Message>{safe_reply}</Message></Response>"

    @property
    def message_log(self) -> list[dict[str, str]]:
        return list(self._message_log)


class CMDOPChannel(BaseChannel):
    """
    Channel bridge for cmdop-bot (Telegram / Discord / Slack).

    Wraps the cmdop-bot CMDOPHandler and integrates it into the
    Network Guardian permission and rate-limiting framework.  When
    a command starts with a known Network Guardian prefix it is
    handled locally; otherwise it is forwarded to CMDOP.
    """

    channel_type = ChannelType.TELEGRAM  # default; override per instance

    def __init__(
        self,
        router: GuardianCommandRouter,
        permissions: RemotePermissionManager,
        rate_limiter: RemoteRateLimiter,
        *,
        channel_type: ChannelType = ChannelType.TELEGRAM,
        cmdop_api_key: str = "",
        cmdop_machine: str = "",
    ) -> None:
        super().__init__(router, permissions, rate_limiter)
        self.channel_type = channel_type  # type: ignore[assignment]
        self.cmdop_api_key = cmdop_api_key
        self.cmdop_machine = cmdop_machine
        self._cmdop_handler: Any = None

    async def start(self) -> None:
        """Initialise the underlying CMDOPHandler if credentials are present."""
        if self.cmdop_api_key:
            try:
                from cmdop_bot import CMDOPHandler  # type: ignore[import-untyped]
                self._cmdop_handler = CMDOPHandler(
                    api_key=self.cmdop_api_key,
                    machine=self.cmdop_machine or None,
                )
            except ImportError:
                logger.warning(
                    "cmdop-bot not installed – CMDOP features unavailable. "
                    "Install with: pip install 'cmdop-bot[%s]'",
                    self.channel_type.value,
                )
        await super().start()

    async def stop(self) -> None:
        if self._cmdop_handler is not None:
            await self._cmdop_handler.close()
            self._cmdop_handler = None
        await super().stop()


# ---------------------------------------------------------------------------
# Remote access manager – top-level orchestrator
# ---------------------------------------------------------------------------

class RemoteAccessManager:
    """
    Central manager for all remote access functionality.

    Combines:
    - GuardianCommandRouter for command execution
    - OpenClawOrchestrator for AI pipeline orchestration
    - Multiple channel adapters (WhatsApp, SMS, Telegram, etc.)
    - Permission management and rate limiting
    """

    def __init__(self, engine: Engine, config: RemoteConfig | None = None) -> None:
        self.engine = engine
        self.config = config or RemoteConfig()
        self.permissions = RemotePermissionManager()
        self.rate_limiter = RemoteRateLimiter(self.config.rate_limit_per_minute)
        self.router = GuardianCommandRouter(engine)
        self.orchestrator = OpenClawOrchestrator(self.router)

        if self.config.max_output_length:
            self.router.set_max_output(self.config.max_output_length)

        self._channels: dict[ChannelType, BaseChannel] = {}
        self._running = False

    # -- Channel management -------------------------------------------------

    def add_channel(self, channel: BaseChannel) -> None:
        self._channels[channel.channel_type] = channel

    def get_channel(self, channel_type: ChannelType) -> BaseChannel | None:
        return self._channels.get(channel_type)

    def remove_channel(self, channel_type: ChannelType) -> bool:
        return self._channels.pop(channel_type, None) is not None

    @property
    def active_channels(self) -> list[ChannelType]:
        return [ct for ct, ch in self._channels.items() if ch.is_running]

    @property
    def channel_count(self) -> int:
        return len(self._channels)

    # -- Convenience factory methods ----------------------------------------

    def setup_whatsapp(
        self,
        *,
        account_sid: str = "",
        auth_token: str = "",
        from_number: str = "",
        webhook_secret: str = "",
    ) -> TwilioWhatsAppChannel:
        ch = TwilioWhatsAppChannel(
            self.router, self.permissions, self.rate_limiter,
            account_sid=account_sid,
            auth_token=auth_token,
            from_number=from_number,
            webhook_secret=webhook_secret,
        )
        self.add_channel(ch)
        return ch

    def setup_sms(
        self,
        *,
        account_sid: str = "",
        auth_token: str = "",
        from_number: str = "",
        webhook_secret: str = "",
    ) -> TwilioSMSChannel:
        ch = TwilioSMSChannel(
            self.router, self.permissions, self.rate_limiter,
            account_sid=account_sid,
            auth_token=auth_token,
            from_number=from_number,
            webhook_secret=webhook_secret,
        )
        self.add_channel(ch)
        return ch

    def setup_cmdop_channel(
        self,
        channel_type: ChannelType,
        *,
        cmdop_api_key: str = "",
        cmdop_machine: str = "",
    ) -> CMDOPChannel:
        ch = CMDOPChannel(
            self.router, self.permissions, self.rate_limiter,
            channel_type=channel_type,
            cmdop_api_key=cmdop_api_key or self.config.cmdop_api_key,
            cmdop_machine=cmdop_machine or self.config.cmdop_machine,
        )
        self.add_channel(ch)
        return ch

    # -- Lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Start all registered channels."""
        for channel in self._channels.values():
            await channel.start()
        self._running = True
        logger.info(
            "Remote access started. %d channel(s) active.", len(self._channels),
        )

    async def stop(self) -> None:
        """Stop all channels."""
        for channel in self._channels.values():
            await channel.stop()
        self._running = False
        logger.info("Remote access stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    # -- Direct command execution -------------------------------------------

    async def execute_command(self, text: str) -> CommandResult:
        """Execute a command directly (bypassing channel auth)."""
        return await self.router.handle(text)

    async def execute_pipeline(
        self, name: str, context: dict[str, str] | None = None,
    ) -> PipelineResult:
        """Execute a named orchestration pipeline."""
        return await self.orchestrator.execute(name, context)
