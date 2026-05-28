#!/usr/bin/env python3
"""
Network Guardian — Full System Integration Startup

Runs the complete integrated system on your machine:
- Smart Firewall Agent (autonomous detection & blocking)
- Probe Integration Bridge (threat intelligence feedback)
- Payload Harvester (rule learning from exploits)
- Attack Correlator (discovery + attack matching)
- Defensive Scanner (internal vulnerability testing)
- Web Dashboard (real-time monitoring & control)
- Data Monitoring (metrics collection)

Start this once, then access:
- Dashboard: http://127.0.0.1:8080 (admin / <password>)
- Monitoring: python3 monitor_data.py monitor (in another terminal)
"""

import asyncio
import sys
import signal
import logging
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from network_guardian.core.engine import Engine
from network_guardian.core.events import Event


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("network_guardian.full_system")


class FullSystemCoordinator:
    """Orchestrates all integrated system components."""

    def __init__(self):
        self.engine = None
        self.running = False
        self._cycle_count = 0

    async def initialize(self):
        """Initialize all components."""
        logger.info("=" * 80)
        logger.info("  Network Guardian — Full System Initialization")
        logger.info("=" * 80)

        logger.info("[1/6] Creating core engine...")
        self.engine = Engine()
        logger.info("      ✓ Engine created")

        logger.info("[2/6] Initializing Smart Firewall Agent...")
        fw = self.engine.smart_firewall
        logger.info(f"      ✓ Firewall running (auto_block={fw.auto_block})")

        logger.info("[3/6] Initializing Probe-Firewall Bridge...")
        bridge = self.engine.probe_bridge
        logger.info(f"      ✓ Bridge ready (subscribed to probe events)")

        logger.info("[4/6] Initializing Payload Harvester...")
        harvester = self.engine.payload_harvester
        rules = harvester.get_harvested_rules()
        logger.info(f"      ✓ Harvester ready ({len(rules)} existing rules)")

        logger.info("[5/6] Initializing Attack Correlator...")
        correlator = self.engine.attack_correlator
        logger.info(f"      ✓ Correlator ready")

        logger.info("[6/6] Initializing Defensive Scanner...")
        scanner = self.engine.defensive_scanner
        logger.info(f"      ✓ Scanner ready")

        logger.info("\n" + "=" * 80)
        logger.info("  System Ready — All Components Online")
        logger.info("=" * 80)

        logger.info("\n📊 DASHBOARD ACCESS:")
        logger.info("   URL: http://127.0.0.1:8080")
        logger.info("   Login: admin / <password>")
        logger.info("\n📈 REAL-TIME MONITORING (in another terminal):")
        logger.info("   python3 monitor_data.py monitor")
        logger.info("\n📤 DATA EXPORT (after testing):")
        logger.info("   python3 export_test_data.py")
        logger.info("\n🧪 PROBE INTEGRATION TEST (in another terminal):")
        logger.info("   python3 probe_integration_test.py")
        logger.info("\n" + "=" * 80)

    async def run_coordinator_loop(self):
        """Main coordination loop."""
        self.running = True
        self._cycle_count = 0

        while self.running:
            self._cycle_count += 1

            # Log cycle status periodically
            if self._cycle_count % 12 == 0:  # Every 60 seconds
                fw_stats = self.engine.smart_firewall.get_stats()
                corr_stats = len(self.engine.attack_correlator._correlations)
                harv_stats = len(self.engine.payload_harvester._harvested_rules)
                disc_stats = len(self.engine.probe_bridge._discovered_services)

                logger.info(
                    f"[Cycle {self._cycle_count}] FW: {fw_stats['unique_attackers']} attackers, "
                    f"{fw_stats['total_scanned']} events | "
                    f"Correlations: {corr_stats} | "
                    f"Rules: {harv_stats} | "
                    f"Discoveries: {disc_stats}"
                )

            await asyncio.sleep(5)

    async def shutdown(self):
        """Graceful shutdown."""
        logger.info("\n[*] Shutting down system...")
        self.running = False

        # Persist final state
        logger.info("[*] Persisting final state...")
        self.engine.smart_firewall._persist_ip_history()
        self.engine.payload_harvester._persist_harvested_rules()
        self.engine.attack_correlator._persist_discoveries()
        self.engine.attack_correlator._persist_correlations()
        self.engine.defensive_scanner._persist_scan_results()

        logger.info("[+] System shutdown complete")
        logger.info("[+] Data persisted to ~/.network_guardian/")
        logger.info("[+] Export data with: python3 export_test_data.py")

    def signal_handler(self, sig, frame):
        """Handle Ctrl+C."""
        logger.info("\n[!] Received interrupt signal")
        asyncio.create_task(self.shutdown())


async def main():
    """Main entry point."""
    coordinator = FullSystemCoordinator()

    # Set up signal handlers
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(coordinator.shutdown()))

    try:
        # Initialize
        await coordinator.initialize()

        # Run coordinator loop (monitors system health)
        await coordinator.run_coordinator_loop()

    except KeyboardInterrupt:
        await coordinator.shutdown()
    except Exception as e:
        logger.error(f"System error: {e}", exc_info=True)
        await coordinator.shutdown()
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] System stopped")
