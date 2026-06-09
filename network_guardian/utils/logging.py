# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""Logging configuration for Network Guardian."""

from __future__ import annotations

import logging
import sys


# ANSI colour codes
_CYAN    = "\033[96m"
_RESET   = "\033[0m"


class _CyanFormatter(logging.Formatter):
    """Formatter that wraps every line in cyan ANSI colour."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return f"{_CYAN}{msg}{_RESET}"


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging for the application."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    formatter = _CyanFormatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # stdout instead of stderr — prevents PowerShell from rendering it red
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger("network_guardian")
    root.setLevel(log_level)
    root.addHandler(handler)
