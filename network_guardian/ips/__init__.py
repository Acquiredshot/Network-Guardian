# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Intrusion Prevention System (IPS) — active threat response.

Works in tandem with the IDS to automatically respond to detected
threats.  Supports multiple response actions:

  • **Block** — add source IP to blocklist (firewall rules)
  • **Rate-limit** — throttle traffic from suspicious sources
  • **Quarantine** — isolate host from network segments
  • **Alert-only** — log and notify without active blocking

Includes an auto-expiry mechanism for temporary blocks and an
allowlist to prevent blocking critical infrastructure.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus
from network_guardian.ids import Alert, ThreatCategory
from network_guardian.models.network import Severity

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.ips")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ResponseAction(Enum):
    """Actions the IPS can take in response to threats."""

    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    ALERT_ONLY = "alert_only"
    DROP = "drop"
    RESET = "reset_connection"


class BlockReason(Enum):
    AUTO_IDS = "auto_ids"
    MANUAL = "manual"
    RATE_EXCEEDED = "rate_exceeded"
    BRUTE_FORCE = "brute_force"
    POLICY = "policy_violation"


@dataclass
class BlockEntry:
    """An entry in the IP blocklist."""

    ip: str
    reason: BlockReason
    action: ResponseAction
    severity: Severity
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: float | None = None  # monotonic time; None = permanent
    alert_id: str = ""
    description: str = ""
    hit_count: int = 0

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.monotonic() > self.expires_at

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "reason": self.reason.value,
            "action": self.action.value,
            "severity": self.severity.value,
            "created": self.created.isoformat(),
            "permanent": self.expires_at is None,
            "alert_id": self.alert_id,
            "description": self.description,
            "hit_count": self.hit_count,
        }


@dataclass
class RateLimitEntry:
    """Rate-limiting configuration for a source IP."""

    ip: str
    max_requests_per_second: float = 1.0
    burst_size: int = 5
    tokens: float = 5.0
    last_refill: float = field(default_factory=time.monotonic)
    expires_at: float | None = None

    def allow(self) -> bool:
        """Token-bucket rate limiter. Returns True if request is allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.burst_size,
            self.tokens + elapsed * self.max_requests_per_second,
        )
        self.last_refill = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.monotonic() > self.expires_at


@dataclass
class IPSEvent:
    """Record of an IPS action taken."""

    event_id: str
    action: ResponseAction
    target_ip: str
    reason: str
    severity: Severity
    alert_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "action": self.action.value,
            "target_ip": self.target_ip,
            "reason": self.reason,
            "severity": self.severity.value,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Response policy
# ---------------------------------------------------------------------------

# Maps threat categories to automatic response actions and block durations
_DEFAULT_POLICY: dict[ThreatCategory, tuple[ResponseAction, int]] = {
    # category → (action, block_duration_seconds)  0 = permanent
    ThreatCategory.PORT_SCAN:            (ResponseAction.RATE_LIMIT, 300),
    ThreatCategory.BRUTE_FORCE:          (ResponseAction.BLOCK, 1800),
    ThreatCategory.DOS:                  (ResponseAction.BLOCK, 600),
    ThreatCategory.MALWARE:              (ResponseAction.BLOCK, 0),
    ThreatCategory.DATA_EXFIL:           (ResponseAction.BLOCK, 3600),
    ThreatCategory.INJECTION:            (ResponseAction.BLOCK, 3600),
    ThreatCategory.PRIVILEGE_ESCALATION: (ResponseAction.BLOCK, 1800),
    ThreatCategory.LATERAL_MOVEMENT:     (ResponseAction.QUARANTINE, 0),
    ThreatCategory.C2_COMMUNICATION:     (ResponseAction.BLOCK, 0),
    ThreatCategory.POLICY_VIOLATION:     (ResponseAction.ALERT_ONLY, 0),
    ThreatCategory.RECONNAISSANCE:       (ResponseAction.ALERT_ONLY, 0),
    ThreatCategory.UNKNOWN:              (ResponseAction.ALERT_ONLY, 0),
}


# ---------------------------------------------------------------------------
# Intrusion Prevention System
# ---------------------------------------------------------------------------


class IntrusionPreventionSystem:
    """Active threat response engine.

    Listens for IDS alerts and automatically applies response actions
    based on configurable policy.  Maintains blocklists, rate-limiters,
    quarantine lists, and an allowlist of protected IPs.
    """

    DEFAULT_BLOCK_DURATION = 1800  # 30 minutes

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus

        self._blocklist: dict[str, BlockEntry] = {}
        self._rate_limits: dict[str, RateLimitEntry] = {}
        self._quarantine: set[str] = set()
        self._allowlist: set[str] = {"127.0.0.1", "::1"}  # never block loopback
        self._history: list[IPSEvent] = []
        self._event_counter = 0
        self._policy = dict(_DEFAULT_POLICY)
        self._auto_respond = True
        self._running = False

    # -- Allowlist management -------------------------------------------

    def add_to_allowlist(self, ip: str) -> None:
        """Add an IP to the allowlist (never block)."""
        self._allowlist.add(ip)
        # Remove from blocklist if present
        self._blocklist.pop(ip, None)
        self._quarantine.discard(ip)
        logger.info("IP %s added to IPS allowlist.", ip)

    def remove_from_allowlist(self, ip: str) -> bool:
        if ip in self._allowlist:
            self._allowlist.discard(ip)
            return True
        return False

    @property
    def allowlist(self) -> set[str]:
        return set(self._allowlist)

    # -- Blocking -------------------------------------------------------

    async def block_ip(
        self,
        ip: str,
        reason: BlockReason = BlockReason.MANUAL,
        severity: Severity = Severity.HIGH,
        duration: int | None = None,
        alert_id: str = "",
        description: str = "",
    ) -> BlockEntry | None:
        """Block an IP address. Returns the block entry, or None if allowlisted."""
        if ip in self._allowlist:
            logger.info("IP %s is allowlisted — block refused.", ip)
            return None

        expires = None
        if duration and duration > 0:
            expires = time.monotonic() + duration

        entry = BlockEntry(
            ip=ip,
            reason=reason,
            action=ResponseAction.BLOCK,
            severity=severity,
            expires_at=expires,
            alert_id=alert_id,
            description=description,
        )
        self._blocklist[ip] = entry
        logger.warning("IPS BLOCKED %s — reason=%s duration=%s",
                        ip, reason.value, f"{duration}s" if duration else "permanent")

        ips_event = self._record_event(ResponseAction.BLOCK, ip,
                                        f"Blocked: {reason.value}", severity, alert_id)
        await self.event_bus.publish(Event(
            topic="ips.block",
            data={"entry": entry.as_dict, "event": ips_event.as_dict},
        ))
        return entry

    async def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the blocklist. Returns True if it was blocked."""
        entry = self._blocklist.pop(ip, None)
        if entry is None:
            return False
        logger.info("IPS unblocked %s", ip)
        self._record_event(ResponseAction.ALERT_ONLY, ip, "Unblocked", Severity.INFO)
        await self.event_bus.publish(Event(
            topic="ips.unblock", data={"ip": ip},
        ))
        return True

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        entry = self._blocklist.get(ip)
        if entry is None:
            return False
        if entry.is_expired:
            self._blocklist.pop(ip, None)
            return False
        entry.hit_count += 1
        return True

    @property
    def blocked_ips(self) -> list[BlockEntry]:
        """Return current blocklist (pruning expired)."""
        self._prune_expired()
        return list(self._blocklist.values())

    # -- Rate limiting --------------------------------------------------

    async def rate_limit_ip(
        self,
        ip: str,
        max_rps: float = 1.0,
        burst: int = 5,
        duration: int = 300,
        alert_id: str = "",
    ) -> RateLimitEntry | None:
        """Apply rate limiting to an IP."""
        if ip in self._allowlist:
            return None

        expires = time.monotonic() + duration if duration > 0 else None
        entry = RateLimitEntry(
            ip=ip, max_requests_per_second=max_rps,
            burst_size=burst, tokens=float(burst), expires_at=expires,
        )
        self._rate_limits[ip] = entry
        logger.info("IPS rate-limiting %s at %.1f req/s", ip, max_rps)

        self._record_event(ResponseAction.RATE_LIMIT, ip,
                            f"Rate-limited at {max_rps} req/s", Severity.MEDIUM, alert_id)
        await self.event_bus.publish(Event(
            topic="ips.rate_limit",
            data={"ip": ip, "max_rps": max_rps, "burst": burst},
        ))
        return entry

    def check_rate_limit(self, ip: str) -> bool:
        """Check if a request from IP should be allowed. Returns True if allowed."""
        entry = self._rate_limits.get(ip)
        if entry is None:
            return True
        if entry.is_expired:
            self._rate_limits.pop(ip, None)
            return True
        return entry.allow()

    # -- Quarantine -----------------------------------------------------

    async def quarantine_ip(self, ip: str, alert_id: str = "") -> bool:
        """Isolate an IP. Returns False if allowlisted."""
        if ip in self._allowlist:
            return False
        self._quarantine.add(ip)
        logger.warning("IPS QUARANTINED %s", ip)
        self._record_event(ResponseAction.QUARANTINE, ip,
                            "Quarantined", Severity.CRITICAL, alert_id)
        await self.event_bus.publish(Event(
            topic="ips.quarantine", data={"ip": ip},
        ))
        return True

    def is_quarantined(self, ip: str) -> bool:
        return ip in self._quarantine

    async def release_quarantine(self, ip: str) -> bool:
        if ip not in self._quarantine:
            return False
        self._quarantine.discard(ip)
        logger.info("IPS released %s from quarantine.", ip)
        await self.event_bus.publish(Event(
            topic="ips.quarantine_release", data={"ip": ip},
        ))
        return True

    @property
    def quarantined_ips(self) -> set[str]:
        return set(self._quarantine)

    # -- Policy ---------------------------------------------------------

    def set_policy(self, category: ThreatCategory,
                   action: ResponseAction, duration: int = 0) -> None:
        """Override the response policy for a threat category."""
        self._policy[category] = (action, duration)
        logger.info("IPS policy updated: %s → %s (%ds)",
                     category.value, action.value, duration)

    def set_auto_respond(self, enabled: bool) -> None:
        """Enable or disable automatic responses to IDS alerts."""
        self._auto_respond = enabled
        logger.info("IPS auto-respond %s", "enabled" if enabled else "disabled")

    # -- Automatic response to IDS alerts --------------------------------

    async def handle_ids_alert(self, alert: Alert) -> IPSEvent | None:
        """Respond to an IDS alert based on the configured policy."""
        if not self._auto_respond:
            return None

        ip = alert.source_ip
        if ip in self._allowlist:
            return None

        action, duration = self._policy.get(
            alert.category, (ResponseAction.ALERT_ONLY, 0)
        )

        if action == ResponseAction.BLOCK:
            await self.block_ip(
                ip, reason=BlockReason.AUTO_IDS,
                severity=alert.severity, duration=duration or None,
                alert_id=alert.alert_id,
                description=f"Auto-blocked: {alert.rule_name}",
            )
        elif action == ResponseAction.RATE_LIMIT:
            await self.rate_limit_ip(
                ip, max_rps=1.0, burst=5,
                duration=duration, alert_id=alert.alert_id,
            )
        elif action == ResponseAction.QUARANTINE:
            await self.quarantine_ip(ip, alert_id=alert.alert_id)

        event = self._record_event(
            action, ip,
            f"Auto-response to {alert.rule_name} ({alert.category.value})",
            alert.severity, alert.alert_id,
        )
        return event

    # -- Inspect traffic ------------------------------------------------

    def should_allow(self, source_ip: str) -> bool:
        """Check all enforcement layers. Returns True if traffic is allowed."""
        if source_ip in self._allowlist:
            return True
        if self.is_blocked(source_ip):
            return False
        if self.is_quarantined(source_ip):
            return False
        if not self.check_rate_limit(source_ip):
            return False
        return True

    # -- Internal helpers -----------------------------------------------

    def _record_event(
        self, action: ResponseAction, ip: str, reason: str,
        severity: Severity, alert_id: str = "",
    ) -> IPSEvent:
        self._event_counter += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        event = IPSEvent(
            event_id=f"IPS-{ts}-{self._event_counter:04d}",
            action=action,
            target_ip=ip,
            reason=reason,
            severity=severity,
            alert_id=alert_id,
        )
        self._history.append(event)
        if len(self._history) > 10_000:
            self._history = self._history[-5_000:]
        return event

    def _prune_expired(self) -> None:
        """Remove expired block entries."""
        expired = [ip for ip, e in self._blocklist.items() if e.is_expired]
        for ip in expired:
            self._blocklist.pop(ip, None)
            logger.debug("Block expired for %s", ip)

    # -- Lifecycle ------------------------------------------------------

    async def start(self) -> None:
        """Start the IPS engine."""
        self._running = True
        logger.info(
            "IPS started: auto-respond=%s, allowlist=%d IPs, policies=%d",
            self._auto_respond, len(self._allowlist), len(self._policy),
        )
        await self.event_bus.publish(Event(
            topic="ips.started",
            data={"auto_respond": self._auto_respond,
                  "policies": len(self._policy)},
        ))

    async def stop(self) -> None:
        """Stop the IPS engine."""
        self._running = False
        logger.info(
            "IPS stopped. %d blocks, %d rate-limits, %d quarantined, %d events.",
            len(self._blocklist), len(self._rate_limits),
            len(self._quarantine), len(self._history),
        )

    @property
    def history(self) -> list[IPSEvent]:
        return list(self._history)

    @property
    def stats(self) -> dict[str, Any]:
        self._prune_expired()
        by_action: dict[str, int] = defaultdict(int)
        for e in self._history:
            by_action[e.action.value] += 1

        return {
            "blocked_ips": len(self._blocklist),
            "rate_limited_ips": len(self._rate_limits),
            "quarantined_ips": len(self._quarantine),
            "allowlisted_ips": len(self._allowlist),
            "total_events": len(self._history),
            "auto_respond": self._auto_respond,
            "by_action": dict(by_action),
            "running": self._running,
        }
