#!/usr/bin/env python3
"""
Network Guardian — Complete Local Startup (Cross-Platform)

Starts all components:
- Dashboard (web interface)
- Local Probe (keeps machine online on fleet map)
- System monitoring

Access dashboard at: http://127.0.0.1:8080
Login: admin / <password>

Press Ctrl+C to stop all services.

Works on: Windows, macOS, Linux
"""

import subprocess
import sys
import time
import signal
import logging
import os
import platform
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("network_guardian")

# Store process IDs so we can kill them on exit
processes = []
OS_TYPE = platform.system()  # "Windows", "Darwin", "Linux"


def cleanup(sig=None, frame=None):
    """Kill all child processes on exit (cross-platform)."""
    logger.info("\n[*] Shutting down all services...")
    for proc in processes:
        try:
            if OS_TYPE == "Windows":
                # Windows: use taskkill
                os.system(f"taskkill /F /PID {proc.pid} 2>nul")
            else:
                # Unix-like: use terminate/kill
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception as e:
            logger.warning(f"Error stopping process: {e}")
            try:
                if OS_TYPE != "Windows":
                    proc.kill()
            except:
                pass
    logger.info("[+] All services stopped")
    sys.exit(0)


def main():
    """Start all components."""
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Use relative path (works on any OS and any directory)
    base_dir = Path(__file__).parent

    logger.info("=" * 80)
    logger.info("  Network Guardian — Complete Local Application")
    logger.info(f"  Platform: {OS_TYPE}")
    logger.info("=" * 80)
    logger.info("\n[1/2] Starting Dashboard Server...")
    logger.info("      URL: http://127.0.0.1:8080")
    logger.info("      Login: admin / <password>")

    # Start dashboard (cross-platform)
    dashboard_proc = subprocess.Popen(
        [sys.executable, "start_dashboard.py"],
        cwd=str(base_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    processes.append(dashboard_proc)
    time.sleep(3)

    if dashboard_proc.poll() is not None:
        logger.error("ERROR: Dashboard failed to start!")
        cleanup()
        return

    logger.info("      ✓ Dashboard started")

    logger.info("\n[2/2] Starting Local Probe (Machine Fleet Registration)...")
    logger.info("      Reports every 30 seconds")
    logger.info("      Keeps machine online on fleet map")

    # Start probe (cross-platform)
    probe_proc = subprocess.Popen(
        [sys.executable, "run_local_probe.py"],
        cwd=str(base_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    processes.append(probe_proc)
    time.sleep(2)

    if probe_proc.poll() is not None:
        logger.error("ERROR: Probe failed to start!")
        cleanup()
        return

    logger.info("      ✓ Probe started")

    logger.info("\n" + "=" * 80)
    logger.info("  System Ready — All Components Online")
    logger.info("=" * 80)
    logger.info("\n📊 DASHBOARD ACCESS:")
    logger.info("   URL: http://127.0.0.1:8080")
    logger.info("   Login: admin / <password>")
    logger.info("\n🗺️  FLEET MAP:")
    logger.info("   Dashboard → Fleet page")
    logger.info("   Your Machine: Online")
    logger.info("\n⏹️  TO STOP:")
    logger.info("   Press Ctrl+C")
    logger.info("\n" + "=" * 80 + "\n")

    # Keep processes running and monitor them
    try:
        while True:
            time.sleep(1)

            # Check if any process died unexpectedly
            if dashboard_proc.poll() is not None:
                logger.error("ERROR: Dashboard crashed!")
                cleanup()
                return

            if probe_proc.poll() is not None:
                logger.error("ERROR: Probe crashed!")
                cleanup()
                return
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        cleanup()

