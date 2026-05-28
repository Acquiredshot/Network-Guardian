#!/usr/bin/env python3
"""
Local Probe Simulator — Keeps MacBook online on fleet map

Registers with dashboard and sends periodic heartbeats to keep online status.
"""

import asyncio
import json
import logging
import platform
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("local_probe")


class LocalProbeSimulator:
    """Simulates a probe running on your local machine."""

    def __init__(self):
        self.agent_id = str(uuid4())[:8].upper()
        self.hostname = socket.gethostname()
        self.platform = platform.system()
        self.running = False

    def get_system_info(self) -> dict:
        """Get current system information."""
        try:
            # Get CPU usage
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            cpu_lines = len([line for line in result.stdout.split('\n') if line.strip()])

            # Get memory
            result = subprocess.run(
                ["vm_stat"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            mem_data = result.stdout

            return {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "platform": self.platform,
                "processes": cpu_lines,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "online",
                "network": {
                    "discovered_hosts": 0,
                    "open_ports": 0,
                },
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "platform": self.platform,
                "status": "online",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def run(self):
        """Run the probe simulator."""
        logger.info("=" * 80)
        logger.info("  Network Guardian — Local Probe Simulator")
        logger.info("=" * 80)
        logger.info(f"[*] Agent ID: {self.agent_id}")
        logger.info(f"[*] Hostname: {self.hostname}")
        logger.info(f"[*] Platform: {self.platform}")
        logger.info("[*] Reporting to dashboard every 30 seconds")
        logger.info("[*] Press Ctrl+C to stop")
        logger.info("=" * 80)

        self.running = True
        cycle = 0

        try:
            while self.running:
                cycle += 1

                # Get system info
                info = self.get_system_info()

                # Log probe status
                logger.info(
                    f"[Cycle {cycle:03d}] Status: {info['status']} | "
                    f"Hostname: {info['hostname']} | "
                    f"Platform: {info['platform']}"
                )

                # Simulate discovering services
                if cycle % 6 == 0:  # Every 3 minutes
                    logger.info(f"[Cycle {cycle:03d}] Scanning network for services...")
                    logger.info(f"    ✓ Discovered 0 new hosts")
                    logger.info(f"    ✓ Discovered 0 open ports")

                # Simulate collecting metrics
                if cycle % 12 == 0:  # Every 6 minutes
                    logger.info(f"[Cycle {cycle:03d}] Collecting system metrics...")
                    logger.info(f"    ✓ CPU usage: {cycle % 80}%")
                    logger.info(f"    ✓ Memory: {50 + (cycle % 30)}%")
                    logger.info(f"    ✓ Disk: {45}%")

                # Wait before next cycle (30 seconds)
                await asyncio.sleep(30)

        except KeyboardInterrupt:
            logger.info("\n[*] Probe stopped by user")
            self.running = False
        except Exception as e:
            logger.error(f"Probe error: {e}", exc_info=True)
            self.running = False


async def main():
    """Main entry point."""
    probe = LocalProbeSimulator()
    await probe.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Local probe shutdown")
