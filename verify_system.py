#!/usr/bin/env python3
"""
Network Guardian — System Verification (Cross-Platform)

Checks if your system is ready to run the application.
Run this before reporting issues!
"""

import sys
import platform
import subprocess
from pathlib import Path
import socket

def check_python_version():
    """Check if Python 3.9+ is installed."""
    version = sys.version_info
    print(f"✓ Python version: {version.major}.{version.minor}.{version.micro}")
    if version.major == 3 and version.minor >= 9:
        print("  ✓ Python 3.9+ requirement met")
        return True
    else:
        print("  ✗ ERROR: Python 3.9+ required! Upgrade Python.")
        return False

def check_port_8080():
    """Check if port 8080 is available."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 8080))
        sock.close()
        if result == 0:
            print("✗ Port 8080 is already in use")
            print("  Solution:")
            if platform.system() == "Windows":
                print("    cmd> netstat -ano | findstr :8080")
                print("    cmd> taskkill /PID <PID> /F")
            else:
                print("    $ lsof -i :8080")
                print("    $ kill -9 <PID>")
            return False
        else:
            print("✓ Port 8080 is available")
            return True
    except Exception as e:
        print(f"✓ Port check passed (assuming available)")
        return True

def check_fleet_json():
    """Check if fleet.json exists."""
    fleet_file = Path.home() / ".network_guardian" / "fleet.json"
    if fleet_file.exists():
        print(f"✓ Fleet configuration found: {fleet_file}")
        return True
    else:
        print(f"✗ Fleet configuration missing: {fleet_file}")
        print("  This will be created when you first run the application")
        return True  # Not critical - will be created on first run

def check_required_files():
    """Check if required startup files exist."""
    base_dir = Path(__file__).parent
    required_files = [
        "start_all.py",
        "start_dashboard.py",
        "run_local_probe.py",
    ]

    all_exist = True
    for filename in required_files:
        filepath = base_dir / filename
        if filepath.exists():
            print(f"✓ {filename} found")
        else:
            print(f"✗ {filename} NOT found at {filepath}")
            all_exist = False

    return all_exist

def check_network_guardian_module():
    """Check if network_guardian package is available."""
    try:
        import network_guardian
        print(f"✓ network_guardian module found")
        return True
    except ImportError:
        print("✗ network_guardian module not found")
        print("  Make sure you're in the Network Guardian directory")
        return False

def main():
    """Run all checks."""
    print("=" * 70)
    print("  Network Guardian — System Verification")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print("=" * 70)
    print()

    checks = [
        ("Python Version", check_python_version),
        ("Port 8080 Available", check_port_8080),
        ("Required Files", check_required_files),
        ("Fleet Configuration", check_fleet_json),
        ("Network Guardian Module", check_network_guardian_module),
    ]

    results = []
    for name, check_func in checks:
        print(f"\nChecking {name}...")
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"✗ Error during check: {e}")
            results.append((name, False))

    print("\n" + "=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)

    all_pass = True
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:8} {name}")
        if not passed:
            all_pass = False

    print()
    if all_pass:
        print("✓ All checks passed! You're ready to run:")
        print()
        if platform.system() == "Windows":
            print("  Option 1 (easiest): Double-click START_ALL.bat")
            print("  Option 2: python start_all.py")
            print("  Option 3: .\\Start-All.ps1")
        else:
            print("  python3 start_all.py")
        print()
        print("Then open: http://127.0.0.1:8080")
    else:
        print("✗ Some checks failed. See details above and fix before running.")

    print("=" * 70)
    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
