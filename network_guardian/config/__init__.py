"""
Network Guardian Configuration.

Centralized configuration management with defaults, environment variable
overrides, and config file support.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScanConfig:
    """Network scanning settings."""

    timeout: float = 5.0
    max_concurrent: int = 50
    port_range: str = "1-1024"
    ping_count: int = 3
    subnet_masks: list[str] = field(default_factory=lambda: ["24"])


@dataclass
class MonitorConfig:
    """Monitoring and alerting settings."""

    poll_interval: float = 30.0
    anomaly_threshold: float = 2.0  # std deviations
    retention_hours: int = 168  # 7 days
    alert_cooldown: float = 300.0  # seconds


@dataclass
class SecurityConfig:
    """Security-related settings."""

    encrypt_reports: bool = True
    api_key_env: str = "NETWORK_GUARDIAN_API_KEY"
    max_login_attempts: int = 5
    session_timeout: int = 3600


@dataclass
class Config:
    """Root configuration for Network Guardian."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    log_level: str = "INFO"
    data_dir: Path = field(default_factory=lambda: Path.home() / ".network_guardian")

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load configuration from a YAML file, falling back to defaults.

        Environment variables override file values using the prefix
        ``NETWORK_GUARDIAN_`` (e.g. ``NETWORK_GUARDIAN_LOG_LEVEL``).
        """
        cfg = cls()

        if path is not None:
            config_path = Path(path)
            if config_path.is_file():
                with open(config_path, "r") as f:
                    raw: dict[str, Any] = yaml.safe_load(f) or {}
                cfg = _apply_dict(cfg, raw)

        # Environment overrides
        env_level = os.environ.get("NETWORK_GUARDIAN_LOG_LEVEL")
        if env_level:
            cfg.log_level = env_level

        env_data = os.environ.get("NETWORK_GUARDIAN_DATA_DIR")
        if env_data:
            cfg.data_dir = Path(env_data)

        return cfg


def _apply_dict(cfg: Config, raw: dict[str, Any]) -> Config:
    """Apply a raw dict (from YAML) onto the Config dataclass."""
    if "log_level" in raw:
        cfg.log_level = str(raw["log_level"])
    if "data_dir" in raw:
        cfg.data_dir = Path(raw["data_dir"])

    _apply_section(cfg.scan, raw.get("scan"))
    _apply_section(cfg.monitor, raw.get("monitor"))
    _apply_section(cfg.security, raw.get("security"))

    return cfg


def _apply_section(section: Any, values: Any) -> None:
    """Apply a dict of values to a dataclass section."""
    if not isinstance(values, dict):
        return
    for k, v in values.items():
        if hasattr(section, k):
            setattr(section, k, v)
