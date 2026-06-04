#!/usr/bin/env python3
"""
Local Probe — Keeps machine online on fleet map (Cross-Platform)

Works on: Windows, macOS, Linux
"""

import subprocess
import sys
import time
import logging
from pathlib import Path
import os
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("local_probe")


def run_local_probe():
    """Run probe with local configuration, restarting if it crashes."""
    port = os.environ.get("PORT", "8080")
    base_url = f"http://127.0.0.1:{port}"
    interval = 30  # Report every 30 seconds

    # Load the actual fleet key from fleet.json (required for signature verification)
    fleet_file = Path.home() / ".network_guardian" / "fleet.json"
    fleet_key = ""
    if fleet_file.exists():
        try:
            with open(fleet_file) as f:
                data = json.load(f)
                fleet_key = data.get("fleet_key", "")
        except Exception as e:
            logger.error(f"Could not load fleet key: {e}")
            logger.error("Cannot start probe without valid fleet key")
            return

    if not fleet_key:
        logger.error("Fleet key not found in ~/.network_guardian/fleet.json")
        return

    # Set up environment - use relative path from current script
    probe_dir = Path(__file__).parent
    env = os.environ.copy()
    env["PYTHONPATH"] = str(probe_dir)

    logger.info("=" * 80)
    logger.info("  Network Guardian — Local Probe for Machine")
    logger.info("=" * 80)
    logger.info(f"[*] Base URL: {base_url}")
    logger.info(f"[*] Report Interval: {interval}s")
    logger.info("[*] Probe will stay online and report continuously")
    logger.info("[*] Press Ctrl+C to stop")
    logger.info("=" * 80)

    attempt = 0
    while True:
        attempt += 1
        logger.info(f"\n[Attempt {attempt}] Starting probe...")

        cmd = [
            sys.executable,
            "-m", "network_guardian.agent.probe",
            "--base", base_url,
            "--key", fleet_key,  # Use the actual fleet key for signature verification
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
        run_local_probe()
    except KeyboardInterrupt:
        print("\n[*] Local probe shutdown")


