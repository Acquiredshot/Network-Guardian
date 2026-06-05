# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
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
class SaaSConfig:
    """SaaS platform settings."""

    mode: str = "standalone"
    database_url: str = ""
    jwt_secret: str = ""
    jwt_issuer: str = "network-guardian"
    jwt_audience: str = "network-guardian-api"
    access_token_ttl: int = 3600
    app_base_url: str = "http://127.0.0.1:8080"
    stripe_public_key: str = ""
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    billing_success_url: str = "http://127.0.0.1:8080/app?billing=success"
    billing_cancel_url: str = "http://127.0.0.1:8080/app?billing=cancel"


@dataclass
class Config:
    """Root configuration for Network Guardian."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    saas: SaaSConfig = field(default_factory=SaaSConfig)

    log_level: str = "INFO"
    data_dir: Path = field(default_factory=lambda: Path.home() / ".network_guardian")

    # Shadow / Learning Mode
    # When True, all enforcement actions (block verdicts, TCP severance, IPS
    # blocks triggered by the sandbox) are suppressed.  Detections are still
    # scored, logged, and published on the event bus so operators can observe
    # baseline behaviour before activating strict inline blocking.
    # Set via YAML key ``shadow_mode: true`` or env var
    # ``NETWORK_GUARDIAN_SHADOW_MODE=1``.
    shadow_mode: bool = False

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

        env_shadow = os.environ.get("NETWORK_GUARDIAN_SHADOW_MODE")
        if env_shadow and env_shadow.lower() in ("1", "true", "yes"):
            cfg.shadow_mode = True

        env_saas_mode = os.environ.get("NG_MODE")
        if env_saas_mode:
            cfg.saas.mode = env_saas_mode

        env_database_url = os.environ.get("DATABASE_URL")
        if env_database_url:
            cfg.saas.database_url = env_database_url

        env_jwt_secret = os.environ.get("JWT_SECRET")
        if env_jwt_secret:
            cfg.saas.jwt_secret = env_jwt_secret

        env_jwt_issuer = os.environ.get("JWT_ISSUER")
        if env_jwt_issuer:
            cfg.saas.jwt_issuer = env_jwt_issuer

        env_jwt_audience = os.environ.get("JWT_AUDIENCE")
        if env_jwt_audience:
            cfg.saas.jwt_audience = env_jwt_audience

        env_access_ttl = os.environ.get("ACCESS_TOKEN_TTL")
        if env_access_ttl:
            cfg.saas.access_token_ttl = int(env_access_ttl)

        env_app_base_url = os.environ.get("APP_BASE_URL")
        if env_app_base_url:
            cfg.saas.app_base_url = env_app_base_url

        env_stripe_public = os.environ.get("STRIPE_PUBLIC_KEY")
        if env_stripe_public:
            cfg.saas.stripe_public_key = env_stripe_public

        env_stripe_secret = os.environ.get("STRIPE_SECRET_KEY")
        if env_stripe_secret:
            cfg.saas.stripe_secret_key = env_stripe_secret

        env_stripe_webhook = os.environ.get("STRIPE_WEBHOOK_SECRET")
        if env_stripe_webhook:
            cfg.saas.stripe_webhook_secret = env_stripe_webhook

        env_billing_success = os.environ.get("BILLING_SUCCESS_URL")
        if env_billing_success:
            cfg.saas.billing_success_url = env_billing_success

        env_billing_cancel = os.environ.get("BILLING_CANCEL_URL")
        if env_billing_cancel:
            cfg.saas.billing_cancel_url = env_billing_cancel

        return cfg


def _apply_dict(cfg: Config, raw: dict[str, Any]) -> Config:
    """Apply a raw dict (from YAML) onto the Config dataclass."""
    if "log_level" in raw:
        cfg.log_level = str(raw["log_level"])
    if "data_dir" in raw:
        cfg.data_dir = Path(raw["data_dir"])
    if "shadow_mode" in raw:
        cfg.shadow_mode = bool(raw["shadow_mode"])

    _apply_section(cfg.scan, raw.get("scan"))
    _apply_section(cfg.monitor, raw.get("monitor"))
    _apply_section(cfg.security, raw.get("security"))
    _apply_section(cfg.saas, raw.get("saas"))

    return cfg


def _apply_section(section: Any, values: Any) -> None:
    """Apply a dict of values to a dataclass section."""
    if not isinstance(values, dict):
        return
    for k, v in values.items():
        if hasattr(section, k):
            setattr(section, k, v)
