# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
FloodGuard Agent — Probe Packet & Connection Flood Protection

Protects Network Guardian and the host network against connection-table
exhaustion attacks — the exact failure mode that can knock a consumer
router offline when a pen-test tool floods it with probe packets.

Detection capabilities
----------------------
  SYN Flood          — rapid half-open TCP connections per source IP
  UDP Flood          — high-rate UDP datagrams per source IP
  ICMP Flood         — ping / echo floods fed from external probes
  Probe Saturation   — pen-test style scans exhausting router NAT tables
  Table Exhaustion   — total connections approaching OS connection limits

Response tiers (escalating)
-----------------------------
  Offence 1  → 1-hour block via IPS
  Offence 2  → 6-hour block via IPS
  Offence 3+ → permanent block via IPS

Each detection also:
  • Fires an IDS alert (DOS / RECONNAISSANCE category)
  • Publishes flood.detected or flood.table_exhaustion on the event bus
  • Logs at WARNING level with full context
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PSUTIL_AVAILABLE = False

from network_guardian.core.events import Event

if TYPE_CHECKING:
    from network_guardian.core.events import EventBus
    from network_guardian.ids import IntrusionDetectionSystem
    from network_guardian.ips import IntrusionPreventionSystem

logger = logging.getLogger("network_guardian.agent.flood_guard")


# ---------------------------------------------------------------------------
# Configurable thresholds
# ---------------------------------------------------------------------------

# Events from a single IP within WINDOW_SECONDS that trip the alarm
SYN_FLOOD_THRESHOLD        = 60    # new TCP connections / window
UDP_FLOOD_THRESHOLD        = 120   # UDP packets / window
ICMP_FLOOD_THRESHOLD       = 80    # ICMP packets / window
PROBE_SATURATION_THRESHOLD = 30    # unique destination ports from one source

# Warn when total active connections on the host approach this number
# (consumer routers typically cap at 512–2048 NAT entries)
TABLE_EXHAUSTION_WARNING   = 800

# Sliding window length for per-IP rate tracking
WINDOW_SECONDS = 10.0

# How often to poll active connections
POLL_INTERVAL  = 5.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FloodEvent:
    """Record of a single flood detection."""

    event_id: str
    flood_type: str          # "syn_flood" | "udp_flood" | "icmp_flood" |
                             # "probe_saturation" | "table_exhaustion"
    source_ip: str
    count: int
    threshold: int
    block_duration: int | None   # seconds; None = permanent
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action_taken: str = "detected"

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id":       self.event_id,
            "flood_type":     self.flood_type,
            "source_ip":      self.source_ip,
            "count":          self.count,
            "threshold":      self.threshold,
            "block_duration": self.block_duration,
            "timestamp":      self.timestamp,
            "action_taken":   self.action_taken,
        }


# ---------------------------------------------------------------------------
# Sliding-window counter
# ---------------------------------------------------------------------------

class _SlidingCounter:
    """Thread-safe sliding-window event counter per source IP."""

    def __init__(self, window: float = WINDOW_SECONDS) -> None:
        self._window = window
        self._events:    dict[str, deque[float]] = defaultdict(deque)
        self._port_sets: dict[str, set[int]]     = defaultdict(set)

    def record(self, ip: str, dest_port: int = 0) -> None:
        now = time.monotonic()
        self._events[ip].append(now)
        if dest_port:
            self._port_sets[ip].add(dest_port)

    def count(self, ip: str) -> int:
        """Events for *ip* within the current window."""
        now    = time.monotonic()
        cutoff = now - self._window
        q      = self._events[ip]
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def unique_ports(self, ip: str) -> int:
        return len(self._port_sets.get(ip, set()))

    def reset_ip(self, ip: str) -> None:
        self._events.pop(ip, None)
        self._port_sets.pop(ip, None)

    def all_ips(self) -> list[str]:
        return list(self._events.keys())

    def evict_stale(self) -> None:
        """Remove IPs with no recent traffic to bound memory usage."""
        now    = time.monotonic()
        cutoff = now - self._window
        stale  = [ip for ip, q in self._events.items() if not q or q[-1] < cutoff]
        for ip in stale:
            self._events.pop(ip, None)
            self._port_sets.pop(ip, None)


# ---------------------------------------------------------------------------
# FloodGuard Agent
# ---------------------------------------------------------------------------

class FloodGuardAgent:
    """Monitors connection rates and auto-blocks flooding source IPs.

    Parameters
    ----------
    ids:
        IDS instance — used to fire alerts for each detected flood.
    ips:
        IPS instance — used to block offending IPs.
    event_bus:
        Event bus for flood.detected / flood.table_exhaustion events.
    allowlist:
        IPs that must never be blocked (e.g. gateway, management hosts).
    poll_interval:
        How often (seconds) to sample active connections via psutil.
    """

    def __init__(
        self,
        ids: "IntrusionDetectionSystem",
        ips: "IntrusionPreventionSystem",
        event_bus: "EventBus",
        allowlist: set[str] | None = None,
        poll_interval: float = POLL_INTERVAL,
    ) -> None:
        self._ids           = ids
        self._ips           = ips
        self._event_bus     = event_bus
        self._allowlist: set[str] = allowlist or {"127.0.0.1", "::1"}
        self._poll_interval = poll_interval

        # Per-protocol sliding counters
        self._tcp_counter   = _SlidingCounter()
        self._udp_counter   = _SlidingCounter()
        self._icmp_counter  = _SlidingCounter()
        self._probe_counter = _SlidingCounter()   # unique dest ports per IP

        # Escalation: how many flood offences each IP has committed
        self._offences: dict[str, int] = defaultdict(int)

        # Duplicate-alert suppression
        self._suppressed: dict[str, float] = {}
        self._suppress_window = 30.0

        self._history: list[FloodEvent] = []
        self._event_counter = 0
        self._running = False
        self._task: asyncio.Task[None] | None = None

    # -- Lifecycle -------------------------------------------------------

    def start(self) -> None:
        """Start the background polling loop."""
        if self._running:
            return
        self._running = True
        self._task    = asyncio.ensure_future(self._loop())
        logger.info(
            "[FloodGuard] Started — poll=%.0fs | syn≥%d udp≥%d icmp≥%d "
            "probe_ports≥%d | window=%.0fs",
            self._poll_interval,
            SYN_FLOOD_THRESHOLD, UDP_FLOOD_THRESHOLD, ICMP_FLOOD_THRESHOLD,
            PROBE_SATURATION_THRESHOLD, WINDOW_SECONDS,
        )

    async def stop(self) -> None:
        """Stop the background loop gracefully."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[FloodGuard] Stopped.")

    # -- Main polling loop ----------------------------------------------

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._scan_connections()
                # Evict stale entries to keep memory bounded
                self._tcp_counter.evict_stale()
                self._udp_counter.evict_stale()
                self._probe_counter.evict_stale()
            except asyncio.CancelledError:
                break
            except Exception as exc:  # pragma: no cover
                logger.debug("[FloodGuard] Scan error: %s", exc)
            await asyncio.sleep(self._poll_interval)

    # -- Connection scanning --------------------------------------------

    async def _scan_connections(self) -> None:
        """Sample active connections via psutil and evaluate thresholds."""
        if not _PSUTIL_AVAILABLE:
            return

        loop  = asyncio.get_event_loop()
        conns = await loop.run_in_executor(None, self._get_connections)

        total        = len(conns)
        seen_tcp_ips: set[str] = set()
        seen_udp_ips: set[str] = set()

        for conn in conns:
            raddr = getattr(conn, "raddr", None)
            if not raddr or not getattr(raddr, "ip", None):
                continue
            remote_ip   = raddr.ip
            remote_port = getattr(raddr, "port", 0)
            laddr       = getattr(conn, "laddr", None)
            local_port  = getattr(laddr, "port", 0) if laddr else 0

            if remote_ip in self._allowlist:
                continue

            conn_type = str(getattr(conn, "type", "")).upper()
            if "UDP" in conn_type:
                self._udp_counter.record(remote_ip, local_port)
                seen_udp_ips.add(remote_ip)
            else:
                self._tcp_counter.record(remote_ip, remote_port)
                self._probe_counter.record(remote_ip, remote_port)
                seen_tcp_ips.add(remote_ip)

        # Global connection table exhaustion check
        if total >= TABLE_EXHAUSTION_WARNING:
            await self._handle_table_exhaustion(total)

        # Per-IP threshold checks
        for ip in seen_tcp_ips | seen_udp_ips:
            if ip in self._allowlist:
                continue

            tcp_count    = self._tcp_counter.count(ip)
            udp_count    = self._udp_counter.count(ip)
            unique_ports = self._probe_counter.unique_ports(ip)

            if tcp_count >= SYN_FLOOD_THRESHOLD:
                await self._handle_flood(ip, "syn_flood",        tcp_count,    SYN_FLOOD_THRESHOLD)
            if udp_count >= UDP_FLOOD_THRESHOLD:
                await self._handle_flood(ip, "udp_flood",        udp_count,    UDP_FLOOD_THRESHOLD)
            if unique_ports >= PROBE_SATURATION_THRESHOLD:
                await self._handle_flood(ip, "probe_saturation", unique_ports, PROBE_SATURATION_THRESHOLD)

    @staticmethod
    def _get_connections() -> list[Any]:
        """Collect active connections (runs in executor thread)."""
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, Exception):
            return []

    # -- Flood response -------------------------------------------------

    async def _handle_flood(
        self,
        source_ip: str,
        flood_type: str,
        count: int,
        threshold: int,
    ) -> None:
        """Fire an alert, escalate a block, and publish a flood event."""
        # Suppress duplicate alerts within the suppression window
        key = f"{flood_type}:{source_ip}"
        now = time.monotonic()
        if now - self._suppressed.get(key, 0.0) < self._suppress_window:
            return
        self._suppressed[key] = now

        # Escalating block duration
        self._offences[source_ip] += 1
        offence = self._offences[source_ip]
        if offence == 1:
            block_duration: int | None = 3600     # 1 hour
        elif offence == 2:
            block_duration = 21600                # 6 hours
        else:
            block_duration = None                 # permanent

        human = (
            f"{block_duration // 3600}h" if block_duration and block_duration >= 3600
            else (str(block_duration) + "s" if block_duration else "permanent")
        )

        logger.warning(
            "[FloodGuard] %s from %s — count=%d threshold=%d offence=#%d block=%s",
            flood_type, source_ip, count, threshold, offence, human,
        )

        # Fire IDS alert
        from network_guardian.ids import Alert, ThreatCategory, DetectionMethod
        from network_guardian.models.network import Severity

        alert = Alert(
            alert_id=self._next_id(),
            rule_name=f"FloodGuard: {flood_type.replace('_', ' ').title()}",
            category=ThreatCategory.DOS,
            severity=Severity.CRITICAL,
            source_ip=source_ip,
            method=DetectionMethod.ANOMALY,
            description=(
                f"{flood_type.replace('_', ' ').title()} detected from {source_ip}: "
                f"{count} events in {WINDOW_SECONDS:.0f}s window "
                f"(threshold={threshold}). Offence #{offence} — blocked {human}."
            ),
            metadata={"count": count, "threshold": threshold, "offence": offence,
                      "block_duration": block_duration},
        )
        await self._ids._fire_alert(alert)

        # Block via IPS
        from network_guardian.ips import BlockReason
        await self._ips.block_ip(
            source_ip,
            reason=BlockReason.AUTO_IDS,
            severity=Severity.CRITICAL,
            duration=block_duration,
            alert_id=alert.alert_id,
            description=f"FloodGuard auto-block: {flood_type} offence #{offence}",
        )

        # Record and publish
        ev = FloodEvent(
            event_id=alert.alert_id,
            flood_type=flood_type,
            source_ip=source_ip,
            count=count,
            threshold=threshold,
            block_duration=block_duration,
            action_taken=f"blocked_{human}",
        )
        self._history.append(ev)
        if len(self._history) > 5_000:
            self._history = self._history[-2_500:]

        await self._event_bus.publish(Event(topic="flood.detected", data=ev.as_dict))

    async def _handle_table_exhaustion(self, total: int) -> None:
        """Warn when the total active connection count reaches dangerous levels."""
        key = "table_exhaustion"
        now = time.monotonic()
        if now - self._suppressed.get(key, 0.0) < 60.0:
            return
        self._suppressed[key] = now

        logger.warning(
            "[FloodGuard] CONNECTION TABLE WARNING — %d active connections "
            "(threshold=%d). Router NAT exhaustion risk — check for flooding tools.",
            total, TABLE_EXHAUSTION_WARNING,
        )
        await self._event_bus.publish(Event(
            topic="flood.table_exhaustion",
            data={
                "total_connections": total,
                "threshold":         TABLE_EXHAUSTION_WARNING,
                "timestamp":         datetime.now(timezone.utc).isoformat(),
            },
        ))

    # -- External packet feed (used by probes / packet sensors) ----------

    async def record_packet(
        self,
        source_ip: str,
        protocol: str = "tcp",
        dest_port: int = 0,
    ) -> None:
        """Feed a raw packet observation into the flood counters.

        Called by probe agents, packet sensors, or the IDS pipeline to
        count packets that psutil may not see (e.g. ICMP, UDP-only flows).
        """
        if source_ip in self._allowlist:
            return

        proto = protocol.lower()
        if proto == "icmp":
            self._icmp_counter.record(source_ip)
            c = self._icmp_counter.count(source_ip)
            if c >= ICMP_FLOOD_THRESHOLD:
                await self._handle_flood(source_ip, "icmp_flood", c, ICMP_FLOOD_THRESHOLD)
        elif proto == "udp":
            self._udp_counter.record(source_ip, dest_port)
            c = self._udp_counter.count(source_ip)
            if c >= UDP_FLOOD_THRESHOLD:
                await self._handle_flood(source_ip, "udp_flood", c, UDP_FLOOD_THRESHOLD)
        else:
            self._tcp_counter.record(source_ip, dest_port)
            self._probe_counter.record(source_ip, dest_port)
            tcp_c   = self._tcp_counter.count(source_ip)
            probe_c = self._probe_counter.unique_ports(source_ip)
            if tcp_c >= SYN_FLOOD_THRESHOLD:
                await self._handle_flood(source_ip, "syn_flood", tcp_c, SYN_FLOOD_THRESHOLD)
            if probe_c >= PROBE_SATURATION_THRESHOLD:
                await self._handle_flood(source_ip, "probe_saturation", probe_c,
                                         PROBE_SATURATION_THRESHOLD)

    # -- Helpers --------------------------------------------------------

    def _next_id(self) -> str:
        self._event_counter += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"FG-{ts}-{self._event_counter:04d}"

    def add_to_allowlist(self, ip: str) -> None:
        """Prevent an IP from ever being flood-blocked."""
        self._allowlist.add(ip)

    def remove_from_allowlist(self, ip: str) -> bool:
        if ip in self._allowlist:
            self._allowlist.discard(ip)
            return True
        return False

    @property
    def history(self) -> list[FloodEvent]:
        return list(self._history)

    @property
    def offences(self) -> dict[str, int]:
        return dict(self._offences)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "running":             self._running,
            "total_flood_events":  len(self._history),
            "unique_offenders":    len(self._offences),
            "top_offenders":       sorted(
                self._offences.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "psutil_available":    _PSUTIL_AVAILABLE,
        }
