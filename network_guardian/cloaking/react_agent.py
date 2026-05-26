# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
ReAct Cloaking Agent — Observe → Reason → Act → Learn.

An agentic loop that continuously monitors the live network environment
and adapts the cloaking system in real time:

  1. **Observe** — traceroute, interface scan, gateway detection, latency probes
  2. **Reason**  — classify network type, assess exposure, pick cloaking strategy
  3. **Act**     — set mode, build proxy chain from real hops, rotate sources, create identities
  4. **Learn**   — persist network fingerprints and outcomes for faster adaptation next time

This is the core intelligence layer that makes Network Guardian agentic —
it grows smarter with every network it encounters.
"""

from __future__ import annotations

import asyncio
import json
import logging
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian.cloaking.react")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class NetworkHop:
    """A real network hop discovered via traceroute."""

    hop_number: int
    ip: str
    hostname: str
    latency_ms: float
    is_alive: bool = True


@dataclass
class NetworkObservation:
    """A snapshot of the current network environment."""

    timestamp: str
    local_ip: str
    gateway_ip: str
    public_ip: str
    dns_servers: list[str]
    hops: list[NetworkHop]
    interface: str
    ssid: str
    network_type: str  # "hotspot", "home", "corporate", "public", "unknown"
    latency_to_gateway_ms: float
    latency_to_internet_ms: float

    def fingerprint(self) -> str:
        """Unique identifier for this network based on gateway + public IP."""
        return f"{self.gateway_ip}|{self.public_ip}"


@dataclass
class ReActStep:
    """A single step in the ReAct reasoning chain."""

    phase: str  # "observe", "reason", "act", "learn"
    thought: str
    detail: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class NetworkProfile:
    """Learned profile for a specific network."""

    fingerprint: str
    network_type: str
    first_seen: str
    last_seen: str
    times_connected: int = 1
    avg_gateway_latency: float = 0.0
    avg_internet_latency: float = 0.0
    avg_hop_count: int = 0
    recommended_mode: str = "full"
    known_hops: list[dict[str, Any]] = field(default_factory=list)
    threat_score: float = 0.0  # 0.0 (safe) to 1.0 (hostile)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Network probing tools (the "hands" of the agent)
# ---------------------------------------------------------------------------


def _get_local_ip() -> str:
    """Get the local IP by connecting to an external address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def _get_gateway() -> str:
    """Get the default gateway IP."""
    try:
        if platform.system() == "Darwin":
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                timeout=5, stderr=subprocess.DEVNULL, text=True,
            )
            for line in out.splitlines():
                if "gateway" in line.lower():
                    return line.split(":")[-1].strip()
        else:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                timeout=5, stderr=subprocess.DEVNULL, text=True,
            )
            parts = out.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return "unknown"


def _get_public_ip() -> str:
    """Get public IP via a lightweight HTTP check."""
    import urllib.request
    try:
        req = urllib.request.Request(
            "https://api.ipify.org",
            headers={"User-Agent": "NetworkGuardian/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode().strip()
    except Exception:
        return "unknown"


def _get_dns_servers() -> list[str]:
    """Read DNS servers from resolv.conf or scutil."""
    servers: list[str] = []
    try:
        if platform.system() == "Darwin":
            out = subprocess.check_output(
                ["scutil", "--dns"], timeout=5,
                stderr=subprocess.DEVNULL, text=True,
            )
            for line in out.splitlines():
                if "nameserver" in line.lower():
                    ip = line.split(":")[-1].strip()
                    if ip and ip not in servers:
                        servers.append(ip)
        else:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        ip = line.split()[1]
                        if ip not in servers:
                            servers.append(ip)
    except Exception:
        pass
    return servers[:4]


def _get_current_ssid() -> str:
    """Get current WiFi SSID."""
    try:
        if platform.system() == "Darwin":
            out = subprocess.check_output(
                ["/usr/sbin/system_profiler", "SPAirPortDataType", "-json"],
                timeout=10, stderr=subprocess.DEVNULL, text=True,
            )
            data = json.loads(out)
            for iface in data.get("SPAirPortDataType", []):
                for info in iface.get("spairport_airport_interfaces", []):
                    current = info.get("spairport_current_network_information", {})
                    for key, net in current.items():
                        if isinstance(net, dict) and "_name" in net:
                            return net["_name"]
                        elif isinstance(net, dict):
                            # Some macOS versions nest differently
                            for sub_key, sub_val in net.items():
                                if isinstance(sub_val, dict) and "_name" in sub_val:
                                    return sub_val["_name"]
    except Exception:
        pass
    # Fallback: try networksetup
    try:
        if platform.system() == "Darwin":
            out = subprocess.check_output(
                ["networksetup", "-getairportnetwork", "en0"],
                timeout=5, stderr=subprocess.DEVNULL, text=True,
            )
            # Output: "Current Wi-Fi Network: MyNetwork"
            if ":" in out:
                return out.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def _get_interface() -> str:
    """Get the active network interface name."""
    try:
        if platform.system() == "Darwin":
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                timeout=5, stderr=subprocess.DEVNULL, text=True,
            )
            for line in out.splitlines():
                if "interface" in line.lower():
                    return line.split(":")[-1].strip()
    except Exception:
        pass
    return "unknown"


def _ping_latency(host: str, count: int = 3) -> float:
    """Measure average latency to a host in ms."""
    try:
        flag = "-c" if platform.system() != "Windows" else "-n"
        out = subprocess.check_output(
            ["ping", flag, str(count), "-W", "2", host],
            timeout=15, stderr=subprocess.DEVNULL, text=True,
        )
        # Parse "avg" from the summary line
        m = re.search(r"[\d.]+/([\d.]+)/[\d.]+", out)
        if m:
            return round(float(m.group(1)), 2)
    except Exception:
        pass
    return -1.0


def _traceroute(target: str = "8.8.8.8", max_hops: int = 15) -> list[NetworkHop]:
    """Run traceroute and parse real hops."""
    hops: list[NetworkHop] = []
    try:
        cmd = (
            ["traceroute", "-n", "-m", str(max_hops), "-w", "2", target]
            if platform.system() == "Darwin"
            else ["traceroute", "-n", "-m", str(max_hops), "-w", "2", target]
        )
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        for line in proc.stdout.splitlines()[1:]:  # skip header
            line = line.strip()
            if not line:
                continue
            # Format: "1  10.0.0.1  1.234 ms  1.456 ms  1.789 ms"
            # or     "2  * * *"
            parts = line.split()
            if not parts:
                continue
            try:
                hop_num = int(parts[0])
            except ValueError:
                continue

            if parts[1] == "*":
                hops.append(NetworkHop(
                    hop_number=hop_num, ip="*", hostname="*",
                    latency_ms=-1, is_alive=False,
                ))
                continue

            ip = parts[1]
            # Collect all latency values from this line
            latencies: list[float] = []
            for p in parts[2:]:
                try:
                    latencies.append(float(p))
                except ValueError:
                    continue
            avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else -1.0

            # Try reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ip

            hops.append(NetworkHop(
                hop_number=hop_num, ip=ip, hostname=hostname,
                latency_ms=avg_lat, is_alive=True,
            ))
    except Exception as e:
        logger.warning("Traceroute failed: %s", e)
    return hops


# ---------------------------------------------------------------------------
# ReAct Cloaking Agent
# ---------------------------------------------------------------------------


class CloakingAgent:
    """Agentic cloaking system using the ReAct pattern.

    Continuously observes the network, reasons about the threat level,
    takes cloaking actions, and learns from each encounter.
    """

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._profiles_path = data_dir / "network_profiles.json"
        self._profiles: dict[str, NetworkProfile] = {}
        self._react_log: list[ReActStep] = []
        self._current_observation: NetworkObservation | None = None
        self._running = False
        self._task: asyncio.Task | None = None
        self._loop_interval = 30  # seconds between observation cycles
        self._load_profiles()

    # -- Persistence ----------------------------------------------------

    def _load_profiles(self) -> None:
        """Load learned network profiles from disk."""
        if self._profiles_path.exists():
            try:
                with open(self._profiles_path) as f:
                    raw = json.load(f)
                for fp, data in raw.items():
                    self._profiles[fp] = NetworkProfile(**data)
                logger.info("Loaded %d learned network profiles", len(self._profiles))
            except Exception as e:
                logger.warning("Could not load network profiles: %s", e)

    def _save_profiles(self) -> None:
        """Persist learned network profiles to disk."""
        try:
            raw = {}
            for fp, p in self._profiles.items():
                raw[fp] = {
                    "fingerprint": p.fingerprint,
                    "network_type": p.network_type,
                    "first_seen": p.first_seen,
                    "last_seen": p.last_seen,
                    "times_connected": p.times_connected,
                    "avg_gateway_latency": p.avg_gateway_latency,
                    "avg_internet_latency": p.avg_internet_latency,
                    "avg_hop_count": p.avg_hop_count,
                    "recommended_mode": p.recommended_mode,
                    "known_hops": p.known_hops,
                    "threat_score": p.threat_score,
                    "notes": p.notes,
                }
            with open(self._profiles_path, "w") as f:
                json.dump(raw, f, indent=2)
        except Exception as e:
            logger.warning("Could not save network profiles: %s", e)

    # -- OBSERVE --------------------------------------------------------

    async def observe(self) -> NetworkObservation:
        """Phase 1: Gather live network intelligence."""
        self._log_step("observe", "Scanning network environment...")

        loop = asyncio.get_event_loop()

        # Run probes concurrently in thread pool
        local_ip, gateway, public_ip, dns, ssid, iface = await asyncio.gather(
            loop.run_in_executor(None, _get_local_ip),
            loop.run_in_executor(None, _get_gateway),
            loop.run_in_executor(None, _get_public_ip),
            loop.run_in_executor(None, _get_dns_servers),
            loop.run_in_executor(None, _get_current_ssid),
            loop.run_in_executor(None, _get_interface),
        )

        # Latency probes
        gw_lat, inet_lat = await asyncio.gather(
            loop.run_in_executor(None, _ping_latency, gateway, 3),
            loop.run_in_executor(None, _ping_latency, "8.8.8.8", 3),
        )

        # Traceroute for real hop discovery
        hops = await loop.run_in_executor(None, _traceroute, "8.8.8.8", 15)

        # Classify network type
        net_type = self._classify_network(local_ip, gateway, ssid, hops)

        obs = NetworkObservation(
            timestamp=datetime.now(timezone.utc).isoformat(),
            local_ip=local_ip,
            gateway_ip=gateway,
            public_ip=public_ip,
            dns_servers=dns,
            hops=hops,
            interface=iface,
            ssid=ssid,
            network_type=net_type,
            latency_to_gateway_ms=gw_lat,
            latency_to_internet_ms=inet_lat,
        )

        self._current_observation = obs
        self._log_step("observe", f"Found {len(hops)} hops, type={net_type}, "
                        f"gateway={gateway}, public={public_ip}, "
                        f"gw_latency={gw_lat}ms, inet_latency={inet_lat}ms",
                        {"local_ip": local_ip, "hops": len(hops), "net_type": net_type})
        return obs

    def _classify_network(self, local_ip: str, gateway: str,
                          ssid: str, hops: list[NetworkHop]) -> str:
        """Classify network type based on observed characteristics."""
        ssid_lower = ssid.lower() if ssid else ""

        # Hotspot indicators
        if any(kw in ssid_lower for kw in ("iphone", "android", "hotspot", "pixel", "galaxy")):
            return "hotspot"
        # 172.20.10.x is Apple hotspot subnet
        if local_ip.startswith("172.20.10."):
            return "hotspot"

        # Corporate indicators: many hops, 10.x or 172.16-31.x
        if local_ip.startswith("10.") and len(hops) > 5:
            return "corporate"

        # Home network: 192.168.x.x with few hops
        if local_ip.startswith("192.168.") and len(hops) <= 8:
            return "home"

        # Public WiFi: common SSID patterns
        if any(kw in ssid_lower for kw in ("free", "guest", "public", "cafe",
                                            "starbucks", "airport", "hotel")):
            return "public"

        return "unknown"

    # -- REASON ---------------------------------------------------------

    def reason(self, obs: NetworkObservation) -> dict[str, Any]:
        """Phase 2: Analyze observation and decide cloaking strategy."""
        fp = obs.fingerprint()
        known = self._profiles.get(fp)

        # Threat assessment
        threat = 0.0
        reasons: list[str] = []

        if obs.network_type == "public":
            threat += 0.7
            reasons.append("Public WiFi — high exposure risk")
        elif obs.network_type == "hotspot":
            threat += 0.3
            reasons.append("Mobile hotspot — moderate trust")
        elif obs.network_type == "corporate":
            threat += 0.5
            reasons.append("Corporate network — monitored environment")
        elif obs.network_type == "home":
            threat += 0.1
            reasons.append("Home network — generally trusted")
        else:
            threat += 0.4
            reasons.append("Unknown network — cautious stance")

        # High hop count = more exposure points
        live_hops = [h for h in obs.hops if h.is_alive]
        if len(live_hops) > 10:
            threat += 0.15
            reasons.append(f"{len(live_hops)} hops — extended path increases exposure")
        elif len(live_hops) > 6:
            threat += 0.05
            reasons.append(f"{len(live_hops)} hops — moderate path length")

        # High latency to gateway suggests congested/distant network
        if obs.latency_to_gateway_ms > 50:
            threat += 0.1
            reasons.append(f"High gateway latency ({obs.latency_to_gateway_ms}ms)")

        # Previously seen with issues
        if known and known.threat_score > 0.5:
            threat += 0.2
            reasons.append(f"Previously flagged (score: {known.threat_score:.1f})")

        threat = min(threat, 1.0)

        # Decide mode based on threat
        if threat >= 0.7:
            mode = "full"
        elif threat >= 0.5:
            mode = "rotate"
        elif threat >= 0.3:
            mode = "mask"
        else:
            mode = "mask"  # always at least mask on any active network

        strategy = {
            "threat_score": round(threat, 2),
            "reasons": reasons,
            "recommended_mode": mode,
            "network_type": obs.network_type,
            "known_network": known is not None,
            "times_seen": known.times_connected if known else 0,
        }

        self._log_step("reason",
                        f"Threat: {threat:.0%} → mode={mode} ({', '.join(reasons[:2])})",
                        strategy)
        return strategy

    # -- ACT ------------------------------------------------------------

    def act(self, cloak_system: Any, obs: NetworkObservation,
            strategy: dict[str, Any]) -> dict[str, Any]:
        """Phase 3: Apply cloaking actions based on reasoning."""
        from network_guardian.cloaking import CloakMode, ProxyHop, ProxyProtocol

        actions_taken: list[str] = []

        # 1. Set cloaking mode
        mode_str = strategy["recommended_mode"]
        mode = CloakMode(mode_str)
        cloak_system.set_mode(mode)
        actions_taken.append(f"Mode → {mode_str}")

        # 2. Create identity for this network if it doesn't exist
        identity_name = f"{obs.network_type.title()} — {obs.ssid}"
        existing = [i.name for i in cloak_system.list_identities()]
        if identity_name not in existing:
            cloak_system.create_identity(
                name=identity_name,
                mode=mode,
                source_ips=[],
            )
            actions_taken.append(f"Identity created: {identity_name}")

        # 3. Activate the identity for this network
        cloak_system.activate_identity(identity_name)
        actions_taken.append(f"Identity activated: {identity_name}")

        # 4. Populate source pool from observed subnet
        #    (done AFTER identity activation so it doesn't get overwritten)
        if obs.local_ip != "unknown":
            parts = obs.local_ip.rsplit(".", 1)
            base = parts[0]
            for i in range(1, 255):
                cloak_system.add_source_ip(f"{base}.{i}")
            actions_taken.append(f"Source pool: {base}.1-254 ({cloak_system._rotator.pool_size} IPs)")

        # 5. Build proxy chain from REAL traceroute hops
        #    (done AFTER identity activation so it doesn't get overwritten)
        cloak_system.clear_proxy_chain()
        live_hops = [h for h in obs.hops if h.is_alive and h.ip != "*"]
        for hop in live_hops:
            if hop.hop_number <= 2:
                proto = ProxyProtocol.SOCKS5
            elif hop.hop_number <= 5:
                proto = ProxyProtocol.HTTPS
            else:
                proto = ProxyProtocol.HTTP

            cloak_system.add_proxy(ProxyHop(
                host=hop.ip,
                port=self._infer_port(hop, proto),
                protocol=proto,
                latency_ms=hop.latency_ms if hop.latency_ms > 0 else 0.0,
                is_alive=hop.is_alive,
            ))
        actions_taken.append(f"Proxy chain: {len(live_hops)} real hops")

        # 6. Mask gateway and local IPs in logs
        cloak_system.mask_ip(obs.local_ip)
        cloak_system.mask_ip(obs.gateway_ip)
        if obs.public_ip != "unknown":
            cloak_system.mask_ip(obs.public_ip)
        actions_taken.append("Masked local + gateway + public IPs")

        result = {
            "actions": actions_taken,
            "mode": mode_str,
            "proxy_hops": len(live_hops),
            "source_pool": cloak_system._rotator.pool_size,
            "identities": len(cloak_system.list_identities()),
        }

        self._log_step("act", f"Took {len(actions_taken)} actions: {', '.join(actions_taken[:3])}...",
                        result)
        return result

    def _infer_port(self, hop: NetworkHop, proto: Any) -> int:
        """Infer a likely service port based on hop characteristics."""
        # First hop is usually the gateway
        if hop.hop_number == 1:
            return 1080
        # Use standard ports for the protocol
        from network_guardian.cloaking import ProxyProtocol
        if proto == ProxyProtocol.SOCKS5:
            return 1080
        elif proto == ProxyProtocol.HTTPS:
            return 443
        else:
            return 8080

    # -- LEARN ----------------------------------------------------------

    def learn(self, obs: NetworkObservation, strategy: dict[str, Any],
              actions: dict[str, Any]) -> None:
        """Phase 4: Store what we learned about this network."""
        fp = obs.fingerprint()
        now = datetime.now(timezone.utc).isoformat()

        if fp in self._profiles:
            profile = self._profiles[fp]
            profile.last_seen = now
            profile.times_connected += 1
            # Running average of latencies
            n = profile.times_connected
            profile.avg_gateway_latency = round(
                (profile.avg_gateway_latency * (n - 1) + obs.latency_to_gateway_ms) / n, 2,
            )
            profile.avg_internet_latency = round(
                (profile.avg_internet_latency * (n - 1) + obs.latency_to_internet_ms) / n, 2,
            )
            profile.avg_hop_count = round(
                (profile.avg_hop_count * (n - 1) + len(obs.hops)) / n,
            )
            profile.threat_score = strategy["threat_score"]
            profile.recommended_mode = strategy["recommended_mode"]
            # Update known hops
            profile.known_hops = [
                {"ip": h.ip, "hostname": h.hostname, "latency_ms": h.latency_ms,
                 "hop": h.hop_number}
                for h in obs.hops if h.is_alive
            ]
            note = f"[{now[:19]}] Reconnected — threat={strategy['threat_score']:.0%}, mode={strategy['recommended_mode']}"
            profile.notes.append(note)
            # Keep last 20 notes
            profile.notes = profile.notes[-20:]
        else:
            profile = NetworkProfile(
                fingerprint=fp,
                network_type=obs.network_type,
                first_seen=now,
                last_seen=now,
                times_connected=1,
                avg_gateway_latency=obs.latency_to_gateway_ms,
                avg_internet_latency=obs.latency_to_internet_ms,
                avg_hop_count=len(obs.hops),
                recommended_mode=strategy["recommended_mode"],
                known_hops=[
                    {"ip": h.ip, "hostname": h.hostname, "latency_ms": h.latency_ms,
                     "hop": h.hop_number}
                    for h in obs.hops if h.is_alive
                ],
                threat_score=strategy["threat_score"],
                notes=[f"[{now[:19]}] First seen — {obs.network_type}, "
                       f"threat={strategy['threat_score']:.0%}"],
            )
            self._profiles[fp] = profile

        self._save_profiles()
        self._log_step("learn",
                        f"Network {fp[:20]}... seen {profile.times_connected}x, "
                        f"threat={profile.threat_score:.0%}, type={profile.network_type}",
                        {"fingerprint": fp, "times_connected": profile.times_connected})

    # -- Full ReAct cycle -----------------------------------------------

    async def run_cycle(self, cloak_system: Any) -> dict[str, Any]:
        """Execute one full Observe → Reason → Act → Learn cycle."""
        t0 = time.monotonic()

        obs = await self.observe()
        strategy = self.reason(obs)
        actions = self.act(cloak_system, obs, strategy)
        self.learn(obs, strategy, actions)

        elapsed = round(time.monotonic() - t0, 2)
        logger.info("ReAct cycle complete in %.1fs — mode=%s, threat=%.0f%%, %d hops",
                     elapsed, strategy["recommended_mode"],
                     strategy["threat_score"] * 100, actions["proxy_hops"])

        return {
            "cycle_time_s": elapsed,
            "observation": {
                "local_ip": obs.local_ip,
                "gateway_ip": obs.gateway_ip,
                "public_ip": obs.public_ip,
                "ssid": obs.ssid,
                "network_type": obs.network_type,
                "hops": len(obs.hops),
                "latency_gateway_ms": obs.latency_to_gateway_ms,
                "latency_internet_ms": obs.latency_to_internet_ms,
            },
            "reasoning": strategy,
            "actions": actions,
        }

    # -- Continuous loop ------------------------------------------------

    async def start(self, cloak_system: Any) -> None:
        """Start the continuous ReAct loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(cloak_system))
        logger.info("ReAct cloaking agent started (interval=%ds)", self._loop_interval)

    async def stop(self) -> None:
        """Stop the continuous loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("ReAct cloaking agent stopped")

    async def _loop(self, cloak_system: Any) -> None:
        """Background loop running ReAct cycles."""
        # Run first cycle immediately
        try:
            await self.run_cycle(cloak_system)
        except Exception:
            logger.exception("ReAct cycle failed")

        while self._running:
            try:
                await asyncio.sleep(self._loop_interval)
                if not self._running:
                    break
                await self.run_cycle(cloak_system)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("ReAct cycle failed")

    # -- Logging --------------------------------------------------------

    def _log_step(self, phase: str, thought: str,
                  detail: dict[str, Any] | None = None) -> None:
        step = ReActStep(phase=phase, thought=thought, detail=detail or {})
        self._react_log.append(step)
        # Keep last 100 steps
        if len(self._react_log) > 100:
            self._react_log = self._react_log[-100:]
        logger.info("[ReAct/%s] %s", phase.upper(), thought)

    # -- Status for dashboard -------------------------------------------

    @property
    def react_log(self) -> list[dict[str, Any]]:
        return [
            {"phase": s.phase, "thought": s.thought,
             "detail": s.detail, "timestamp": s.timestamp}
            for s in self._react_log
        ]

    @property
    def current_observation(self) -> dict[str, Any] | None:
        if self._current_observation is None:
            return None
        obs = self._current_observation
        return {
            "timestamp": obs.timestamp,
            "local_ip": obs.local_ip,
            "gateway_ip": obs.gateway_ip,
            "public_ip": obs.public_ip,
            "dns_servers": obs.dns_servers,
            "interface": obs.interface,
            "ssid": obs.ssid,
            "network_type": obs.network_type,
            "latency_gateway_ms": obs.latency_to_gateway_ms,
            "latency_internet_ms": obs.latency_to_internet_ms,
            "hop_count": len(obs.hops),
            "hops": [
                {"hop": h.hop_number, "ip": h.ip, "hostname": h.hostname,
                 "latency_ms": h.latency_ms, "alive": h.is_alive}
                for h in obs.hops
            ],
        }

    @property
    def learned_profiles(self) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint": p.fingerprint,
                "network_type": p.network_type,
                "first_seen": p.first_seen,
                "last_seen": p.last_seen,
                "times_connected": p.times_connected,
                "avg_gateway_latency": p.avg_gateway_latency,
                "avg_internet_latency": p.avg_internet_latency,
                "avg_hop_count": p.avg_hop_count,
                "recommended_mode": p.recommended_mode,
                "threat_score": p.threat_score,
                "known_hops": len(p.known_hops),
                "notes": p.notes[-3:],
            }
            for p in self._profiles.values()
        ]

    @property
    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "networks_learned": len(self._profiles),
            "react_steps": len(self._react_log),
            "last_observation": self.current_observation,
            "loop_interval_s": self._loop_interval,
        }
