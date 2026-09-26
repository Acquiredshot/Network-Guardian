#!/usr/bin/env python3
"""
Network Guardian — Complete Local Startup (Cross-Platform)

Starts all components:
- Dashboard (web interface)
- Local Probe (keeps machine online on fleet map)
- System monitoring

Access dashboard at: http://127.0.0.1:8080
Login: admin user (password set in team store)

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
import urllib.request
import urllib.error
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("network_guardian")

# Store process IDs so we can kill them on exit
processes = []
log_streams = []
OS_TYPE = platform.system()  # "Windows", "Darwin", "Linux"


def _open_component_log(base_dir: Path, name: str):
    """Open an append-only log file for a long-running child component."""
    log_dir = base_dir / ".network_guardian" / "runtime_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handle = open(log_dir / f"{name}.log", "a", encoding="utf-8", buffering=1)
    log_streams.append(handle)
    return handle


def _start_component(base_dir: Path, script_name: str, log_name: str) -> subprocess.Popen:
    """Start a child component with stdout/stderr persisted to a log file."""
    log_handle = _open_component_log(base_dir, log_name)
    return subprocess.Popen(
        [sys.executable, script_name],
        cwd=str(base_dir),
        stdout=log_handle,
        stderr=log_handle,
        text=True,
    )


def _is_dashboard_reachable(url: str = "http://127.0.0.1:8080/") -> bool:
    """Return True when dashboard is already serving requests."""
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return 200 <= response.status < 500
    except urllib.error.HTTPError as e:
        # Any non-5xx HTTP response proves something is serving on this port.
        return 200 <= e.code < 500
    except Exception:
        return False


def cleanup(sig=None, frame=None):
    """Kill all child processes on exit (cross-platform)."""
    logger.info("\n[*] Shutting down all services...")
    for proc in processes:
        try:
            if OS_TYPE == "Windows":
                # Windows: stop process without invoking a shell.
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(proc.pid)],
                    capture_output=True,
                    text=True,
                )
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
    for handle in log_streams:
        try:
            handle.close()
        except Exception:
            pass
    logger.info("[+] All services stopped")
    sys.exit(0)


def main():
    """Start all components."""
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Use relative path (works on any OS and any directory)
    base_dir = Path(__file__).parent
    public_defense_mode = (
        "--public-defense" in sys.argv
        or os.environ.get("NG_PUBLIC_DEFENSE", "0").strip().lower() in {"1", "true", "yes", "on"}
    )

    if public_defense_mode:
        logger.info("=" * 80)
        logger.info("  Network Guardian — Public Defense Mode")
        logger.info(f"  Platform: {OS_TYPE}")
        logger.info("=" * 80)
        logger.info("\n[1/1] Starting Full Defense Stack...")
        logger.info("      Mode: Smart firewall + anomaly reasoning + isolation sandbox")
        logger.info("      Dashboard: http://127.0.0.1:8080")

        full_proc = _start_component(base_dir, "run_full_system.py", "full_system")
        processes.append(full_proc)
        time.sleep(4)

        if full_proc.poll() is not None:
            logger.error("Full defense startup error. See .network_guardian/runtime_logs/full_system.log")
            logger.error("ERROR: Full defense stack failed to start!")
            cleanup()
            return

        logger.info("      ✓ Full defense stack started")
        logger.info("\n" + "=" * 80)
        logger.info("  Public Defense Active")
        logger.info("=" * 80)
        logger.info("\n⏹️  TO STOP:")
        logger.info("   Press Ctrl+C")
        logger.info("\n" + "=" * 80 + "\n")

        try:
            while True:
                time.sleep(1)
                if full_proc.poll() is not None:
                    logger.error("ERROR: Full defense stack crashed!")
                    cleanup()
                    return
        except KeyboardInterrupt:
            cleanup()
        return

    logger.info("=" * 80)
    logger.info("  Network Guardian — Complete Local Application")
    logger.info(f"  Platform: {OS_TYPE}")
    logger.info("=" * 80)
    logger.info("\n[1/2] Starting Dashboard Server...")
    logger.info("      URL: http://127.0.0.1:8080")
    logger.info("      Login: admin user (password set in team store)")

    # Start dashboard (cross-platform)
    dashboard_proc = _start_component(base_dir, "start_dashboard.py", "dashboard")
    processes.append(dashboard_proc)
    time.sleep(3)
    dashboard_managed_by_this_process = True

    if dashboard_proc.poll() is not None:
        # If another dashboard is already listening, reuse it instead of aborting startup.
        if _is_dashboard_reachable():
            logger.warning("Dashboard port already in use, reusing existing dashboard at http://127.0.0.1:8080")
            dashboard_managed_by_this_process = False
            processes.remove(dashboard_proc)
        else:
            logger.error("Dashboard startup error. See .network_guardian/runtime_logs/dashboard.log")
            logger.error("ERROR: Dashboard failed to start!")
            cleanup()
            return

    if dashboard_managed_by_this_process:
        logger.info("      ✓ Dashboard started")
    else:
        logger.info("      ✓ Dashboard already running")

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
    logger.info("   Login: admin user (password set in team store)")
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
            if dashboard_managed_by_this_process and dashboard_proc.poll() is not None:
                if _is_dashboard_reachable():
                    logger.warning("Dashboard child exited but the dashboard is still reachable; continuing.")
                    dashboard_managed_by_this_process = False
                    try:
                        processes.remove(dashboard_proc)
                    except ValueError:
                        pass
                else:
                    logger.warning("Dashboard exited unexpectedly; attempting one automatic restart.")
                    try:
                        processes.remove(dashboard_proc)
                    except ValueError:
                        pass
                    dashboard_proc = _start_component(base_dir, "start_dashboard.py", "dashboard")
                    processes.append(dashboard_proc)
                    time.sleep(3)
                    if dashboard_proc.poll() is not None or not _is_dashboard_reachable():
                        logger.error("ERROR: Dashboard crashed and restart failed. See .network_guardian/runtime_logs/dashboard.log")
                        cleanup()
                        return
                    logger.info("Dashboard restarted successfully")

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

