"""
IP Cloaking — network identity obfuscation and privacy.

Provides mechanisms to mask, rotate, and obfuscate IP addresses for
stealth scanning and privacy-preserving operations:

  • **Address masking** — replace real IPs with aliases in logs/reports
  • **Source rotation** — cycle through available source addresses
  • **Proxy chain** — route traffic through configurable proxy hops
  • **Decoy generation** — generate decoy traffic to mask real scans
  • **Identity profiles** — saveable cloaking configurations

All outbound traffic from Network Guardian can optionally be routed
through the cloaking layer for operational security.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.cloaking")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CloakMode(Enum):
    """IP cloaking mode."""

    DISABLED = "disabled"
    MASK = "mask"               # Replace IPs in logs with aliases
    ROTATE = "rotate"           # Cycle through source IPs
    PROXY = "proxy"             # Route through proxy chain
    DECOY = "decoy"             # Generate decoy traffic
    FULL = "full"               # All techniques combined


class ProxyProtocol(Enum):
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    HTTP = "http"
    HTTPS = "https"


@dataclass
class ProxyHop:
    """A single hop in a proxy chain."""

    host: str
    port: int
    protocol: ProxyProtocol = ProxyProtocol.SOCKS5
    username: str = ""
    # Note: credentials should come from env/secrets manager in production
    auth_token_env: str = ""  # env var name for auth
    latency_ms: float = 0.0
    is_alive: bool = True

    @property
    def address(self) -> str:
        return f"{self.protocol.value}://{self.host}:{self.port}"

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol.value,
            "latency_ms": self.latency_ms,
            "is_alive": self.is_alive,
        }


@dataclass
class CloakIdentity:
    """A cloaking identity profile."""

    name: str
    mode: CloakMode
    source_ips: list[str] = field(default_factory=list)
    proxy_chain: list[ProxyHop] = field(default_factory=list)
    decoy_count: int = 3
    mask_salt: str = field(default_factory=lambda: secrets.token_hex(8))
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode.value,
            "source_ips": self.source_ips,
            "proxy_chain": [p.as_dict for p in self.proxy_chain],
            "decoy_count": self.decoy_count,
            "created": self.created.isoformat(),
        }


@dataclass
class DecoyTarget:
    """A decoy scan target used to mask real scan activity."""

    ip: str
    ports: list[int] = field(default_factory=list)
    delay_ms: float = 0.0

    @property
    def as_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "ports": self.ports, "delay_ms": self.delay_ms}


# ---------------------------------------------------------------------------
# IP Masking engine
# ---------------------------------------------------------------------------


class IPMasker:
    """Deterministic IP masking — same input always maps to same alias.

    Uses HMAC-style hashing with a per-session salt so the mapping
    cannot be reversed without the salt, but remains consistent within
    a session for log correlation.
    """

    def __init__(self, salt: str | None = None) -> None:
        self._salt = salt or secrets.token_hex(8)
        self._cache: dict[str, str] = {}
        self._reverse: dict[str, str] = {}

    def mask(self, ip: str) -> str:
        """Return a deterministic masked alias for an IP address."""
        if ip in self._cache:
            return self._cache[ip]

        h = hashlib.sha256(f"{self._salt}:{ip}".encode()).hexdigest()[:8]
        alias = f"cloaked-{h}"
        self._cache[ip] = alias
        self._reverse[alias] = ip
        return alias

    def unmask(self, alias: str) -> str | None:
        """Reverse lookup — only works within the same session."""
        return self._reverse.get(alias)

    def mask_text(self, text: str) -> str:
        """Mask all known IPs that appear in a text string."""
        result = text
        for real_ip, alias in self._cache.items():
            result = result.replace(real_ip, alias)
        return result

    @property
    def mapping_count(self) -> int:
        return len(self._cache)

    def reset(self, new_salt: str | None = None) -> None:
        """Reset all mappings, optionally with a new salt."""
        self._salt = new_salt or secrets.token_hex(8)
        self._cache.clear()
        self._reverse.clear()


# ---------------------------------------------------------------------------
# Source IP rotation
# ---------------------------------------------------------------------------


class SourceRotator:
    """Cycles through available source IP addresses for outgoing connections."""

    def __init__(self, source_ips: list[str] | None = None) -> None:
        self._sources: list[str] = source_ips or []
        self._index = 0

    def add_source(self, ip: str) -> None:
        """Add a source IP to the rotation pool."""
        if ip not in self._sources:
            self._sources.append(ip)

    def remove_source(self, ip: str) -> bool:
        if ip in self._sources:
            self._sources.remove(ip)
            return True
        return False

    def next_source(self) -> str | None:
        """Get the next source IP in rotation."""
        if not self._sources:
            return None
        ip = self._sources[self._index % len(self._sources)]
        self._index += 1
        return ip

    def random_source(self) -> str | None:
        """Pick a random source IP."""
        if not self._sources:
            return None
        # Use secrets for unpredictable selection
        idx = secrets.randbelow(len(self._sources))
        return self._sources[idx]

    @property
    def pool_size(self) -> int:
        return len(self._sources)

    @property
    def sources(self) -> list[str]:
        return list(self._sources)


# ---------------------------------------------------------------------------
# Decoy generator
# ---------------------------------------------------------------------------


class DecoyGenerator:
    """Generates decoy targets and traffic to mask real scan activity.

    When performing a real scan against a target, decoy scans are
    simultaneously launched against plausible random IPs, making it
    harder for an observer to identify the actual target.
    """

    def __init__(self, subnet: str = "192.168.1.0/24", count: int = 3) -> None:
        self._subnet = ipaddress.ip_network(subnet, strict=False)
        self.count = count

    def generate_decoys(
        self,
        real_target: str,
        real_ports: list[int] | None = None,
    ) -> list[DecoyTarget]:
        """Generate decoy targets that look like the real scan target."""
        decoys: list[DecoyTarget] = []
        hosts = list(self._subnet.hosts())
        # Filter out the real target and network/broadcast
        candidates = [str(h) for h in hosts if str(h) != real_target]

        count = min(self.count, len(candidates))
        selected = []
        seen: set[int] = set()
        while len(selected) < count and len(seen) < len(candidates):
            idx = secrets.randbelow(len(candidates))
            if idx not in seen:
                seen.add(idx)
                selected.append(candidates[idx])

        ports = real_ports or [22, 80, 443]
        for ip in selected:
            # Randomise delay to avoid timing correlation
            delay = secrets.randbelow(500) + 100  # 100-600ms
            decoys.append(DecoyTarget(ip=ip, ports=list(ports), delay_ms=delay))

        return decoys

    @property
    def subnet(self) -> str:
        return str(self._subnet)


# ---------------------------------------------------------------------------
# IP Cloaking System (main orchestrator)
# ---------------------------------------------------------------------------


class IPCloakingSystem:
    """Unified IP cloaking and privacy system.

    Combines masking, rotation, proxy chaining, and decoy generation
    into a single orchestrated privacy layer.
    """

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus

        self._mode = CloakMode.DISABLED
        self._masker = IPMasker()
        self._rotator = SourceRotator()
        self._decoy_gen = DecoyGenerator()
        self._proxy_chain: list[ProxyHop] = []
        self._identities: dict[str, CloakIdentity] = {}
        self._active_identity: str | None = None
        self._running = False
        self._stats_masked = 0
        self._stats_rotated = 0
        self._stats_decoys = 0

    # -- Mode control ---------------------------------------------------

    @property
    def mode(self) -> CloakMode:
        return self._mode

    def set_mode(self, mode: CloakMode) -> None:
        """Set the active cloaking mode."""
        old = self._mode
        self._mode = mode
        logger.info("Cloaking mode changed: %s → %s", old.value, mode.value)

    # -- Masking --------------------------------------------------------

    def mask_ip(self, ip: str) -> str:
        """Mask an IP address (returns alias if masking is active)."""
        if self._mode in (CloakMode.MASK, CloakMode.FULL):
            self._stats_masked += 1
            return self._masker.mask(ip)
        return ip

    def unmask_ip(self, alias: str) -> str | None:
        """Reverse-lookup a masked IP."""
        return self._masker.unmask(alias)

    def mask_text(self, text: str) -> str:
        """Mask all known IPs in a block of text."""
        if self._mode in (CloakMode.MASK, CloakMode.FULL):
            return self._masker.mask_text(text)
        return text

    # -- Source rotation ------------------------------------------------

    def get_source_ip(self) -> str | None:
        """Get the next outbound source IP (if rotation is active)."""
        if self._mode in (CloakMode.ROTATE, CloakMode.FULL):
            self._stats_rotated += 1
            return self._rotator.random_source()
        return None

    def add_source_ip(self, ip: str) -> None:
        self._rotator.add_source(ip)

    def remove_source_ip(self, ip: str) -> bool:
        return self._rotator.remove_source(ip)

    # -- Proxy chain ----------------------------------------------------

    def add_proxy(self, proxy: ProxyHop) -> None:
        """Add a proxy to the chain."""
        self._proxy_chain.append(proxy)
        logger.info("Proxy added to chain: %s", proxy.address)

    def remove_proxy(self, index: int) -> ProxyHop | None:
        """Remove a proxy by index."""
        if 0 <= index < len(self._proxy_chain):
            return self._proxy_chain.pop(index)
        return None

    def clear_proxy_chain(self) -> int:
        count = len(self._proxy_chain)
        self._proxy_chain.clear()
        return count

    @property
    def proxy_chain(self) -> list[ProxyHop]:
        return list(self._proxy_chain)

    async def check_proxy_health(self) -> list[dict[str, Any]]:
        """Check connectivity to each proxy in the chain."""
        results: list[dict[str, Any]] = []
        for proxy in self._proxy_chain:
            # In a real implementation, this would attempt a TCP connection
            results.append({
                "address": proxy.address,
                "is_alive": proxy.is_alive,
                "latency_ms": proxy.latency_ms,
            })
        return results

    # -- Decoy generation -----------------------------------------------

    def generate_decoys(
        self, real_target: str, ports: list[int] | None = None,
    ) -> list[DecoyTarget]:
        """Generate decoy targets around a real scan target."""
        if self._mode in (CloakMode.DECOY, CloakMode.FULL):
            decoys = self._decoy_gen.generate_decoys(real_target, ports)
            self._stats_decoys += len(decoys)
            return decoys
        return []

    def set_decoy_subnet(self, subnet: str) -> None:
        """Configure the subnet used for decoy generation."""
        self._decoy_gen = DecoyGenerator(subnet=subnet, count=self._decoy_gen.count)

    def set_decoy_count(self, count: int) -> None:
        """Set the number of decoys generated per real target."""
        self._decoy_gen.count = max(1, count)

    # -- Identity profiles ----------------------------------------------

    def create_identity(
        self,
        name: str,
        mode: CloakMode,
        source_ips: list[str] | None = None,
        proxy_chain: list[ProxyHop] | None = None,
        decoy_count: int = 3,
    ) -> CloakIdentity:
        """Create a named cloaking identity profile."""
        identity = CloakIdentity(
            name=name,
            mode=mode,
            source_ips=source_ips or [],
            proxy_chain=proxy_chain or [],
            decoy_count=decoy_count,
        )
        self._identities[name] = identity
        logger.info("Cloaking identity created: %s (mode=%s)", name, mode.value)
        return identity

    def activate_identity(self, name: str) -> bool:
        """Activate a named identity profile."""
        identity = self._identities.get(name)
        if identity is None:
            return False

        self._mode = identity.mode
        self._masker = IPMasker(salt=identity.mask_salt)
        self._rotator = SourceRotator(list(identity.source_ips))
        self._proxy_chain = list(identity.proxy_chain)
        self._decoy_gen.count = identity.decoy_count
        self._active_identity = name
        logger.info("Activated cloaking identity: %s", name)
        return True

    def list_identities(self) -> list[CloakIdentity]:
        return list(self._identities.values())

    def delete_identity(self, name: str) -> bool:
        if name in self._identities:
            del self._identities[name]
            if self._active_identity == name:
                self._active_identity = None
            return True
        return False

    @property
    def active_identity(self) -> str | None:
        return self._active_identity

    # -- Scan preparation -----------------------------------------------

    def prepare_scan(
        self, target: str, ports: list[int] | None = None,
    ) -> dict[str, Any]:
        """Prepare a cloaked scan configuration.

        Returns a dict with source_ip, decoys, proxy_chain, and
        masked_target for use by scanning subsystems.
        """
        result: dict[str, Any] = {
            "real_target": target,
            "display_target": self.mask_ip(target),
            "source_ip": self.get_source_ip(),
            "decoys": [d.as_dict for d in self.generate_decoys(target, ports)],
            "proxy_chain": [p.as_dict for p in self._proxy_chain],
            "mode": self._mode.value,
        }
        return result

    # -- Lifecycle ------------------------------------------------------

    async def start(self) -> None:
        """Start the cloaking system."""
        self._running = True
        logger.info("IP Cloaking started (mode=%s).", self._mode.value)
        await self.event_bus.publish(Event(
            topic="cloaking.started",
            data={"mode": self._mode.value},
        ))

    async def stop(self) -> None:
        """Stop the cloaking system and clear sensitive state."""
        self._running = False
        self._masker.reset()
        logger.info("IP Cloaking stopped. Masking tables cleared.")

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "mode": self._mode.value,
            "active_identity": self._active_identity,
            "identities": len(self._identities),
            "source_pool_size": self._rotator.pool_size,
            "proxy_chain_length": len(self._proxy_chain),
            "masked_ips": self._masker.mapping_count,
            "stats_masked": self._stats_masked,
            "stats_rotated": self._stats_rotated,
            "stats_decoys": self._stats_decoys,
            "running": self._running,
        }
