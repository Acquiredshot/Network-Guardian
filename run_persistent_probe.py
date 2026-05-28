#!/usr/bin/env python3
"""
Persistent Probe — Keeps your MacBook online on the fleet map

Continuously reports to the dashboard with network metrics and status.
"""

import subprocess
import sys
import time
import logging
from pathlib import Path
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("persistent_probe")


def run_persistent_probe():
    """Run probe in a loop, restarting if it crashes."""
    base_url = "http://127.0.0.1:8080"
    agent_key = "XMibg0I4-local-macbook-probe"
    interval = 30  # Report every 30 seconds

    # Set up environment
    probe_dir = Path(__file__).parent
    env = os.environ.copy()
    env["PYTHONPATH"] = str(probe_dir)

    logger.info("=" * 80)
    logger.info("  Network Guardian — Persistent Probe (MacBook)")
    logger.info("=" * 80)
    logger.info(f"[*] Base URL: {base_url}")
    logger.info(f"[*] Agent Key: {agent_key}")
    logger.info(f"[*] Report Interval: {interval}s")
    logger.info("[*] Probe will stay online and report continuously")
    logger.info("=" * 80)

    attempt = 0
    while True:
        attempt += 1
        logger.info(f"\n[Attempt {attempt}] Starting probe...")

        cmd = [
            sys.executable,
            "-m", "network_guardian.agent.probe",
            "--base", base_url,
            "--key", agent_key,
            "--interval", str(interval),
            "--username", "admin",
            "--password", "<password>",
        ]

        try:
            subprocess.run(cmd, cwd=str(probe_dir), env=env)
        except KeyboardInterrupt:
            logger.info("[*] Probe stopped by user")
            break
        except Exception as e:
            logger.error(f"[!] Probe error: {e}")
            logger.info("[*] Restarting in 5 seconds...")
            time.sleep(5)


if __name__ == "__main__":
    try:
        run_persistent_probe()
    except KeyboardInterrupt:
        print("\n[*] Persistent probe shutdown")
