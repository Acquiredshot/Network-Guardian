"""
Network Guardian — CLI entry point.

Usage:
    network-guardian [OPTIONS]

Options:
    --config PATH    Path to YAML config file
    --log-level LVL  Logging level (DEBUG, INFO, WARNING, ERROR)
    --non-interactive  Run a single audit then exit
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.interface import InteractiveCLI
from network_guardian.utils.logging import setup_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-guardian",
        description="Network Guardian — autonomous network auditing and monitoring assistant",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    parser.add_argument(
        "--audit",
        nargs="+",
        metavar="TARGET",
        help="Run a non-interactive audit against one or more targets, then exit",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        default=False,
        help="Start the web dashboard alongside the interactive CLI",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8080,
        help="Port for the web dashboard (default: 8080)",
    )
    return parser


async def async_main(args: argparse.Namespace) -> int:
    config = Config.load(args.config)

    if args.log_level:
        config.log_level = args.log_level

    setup_logging(config.log_level)

    engine = Engine(config)
    await engine.start()

    try:
        if args.dashboard:
            engine.dashboard.port = args.dashboard_port
            await engine.dashboard.start()

        if args.audit:
            # Non-interactive: run audit and exit
            findings = await engine.auditor.run_audit(args.audit)
            for f in findings:
                print(f"[{f.severity.value.upper()}] {f.title}: {f.description}")
            return 1 if any(f.severity.value in ("high", "critical") for f in findings) else 0
        else:
            # Interactive REPL
            cli = InteractiveCLI(engine)
            await cli.run()
            return 0
    finally:
        await engine.stop()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
