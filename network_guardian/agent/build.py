#!/usr/bin/env python3
"""
Agent Builder — Packages field agents for USB deployment.

Creates a ready-to-deploy USB package that auto-installs and starts
the agent when an employee plugs in the drive and runs the setup script.

Usage:
    python -m network_guardian.agent.build --base http://192.168.1.100:8080
    python -m network_guardian.agent.build --base http://192.168.1.100:8080 --exe

    --exe mode requires PyInstaller and builds a standalone binary.
    Default mode creates a USB folder with probe.py + setup scripts.

WOLFPAK INTERNAL USE ONLY.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def get_fleet_key(base_url: str) -> str:
    """Fetch the fleet key from the base station (requires auth cookie or admin)."""
    print(f"  Fetching fleet key from {base_url}...")
    # For local builds, read from fleet.json directly
    fleet_path = Path.home() / ".network_guardian" / "fleet.json"
    if fleet_path.exists():
        try:
            with open(fleet_path) as f:
                data = json.load(f)
                key = data.get("fleet_key", "")
                if key:
                    return key
        except (json.JSONDecodeError, OSError):
            pass
    print("  WARNING: Could not read fleet key. You'll need to provide it manually.")
    return ""


def build_usb_package(base_url: str, fleet_key: str, output_dir: str = "dist/usb_deploy",
                       interval: int = 60) -> Path:
    """Build a USB deployment folder with probe + auto-setup scripts."""
    out = Path(output_dir)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    agent_dir = Path(__file__).parent

    # Copy probe.py
    shutil.copy2(agent_dir / "probe.py", out / "probe.py")

    # Copy and configure setup scripts
    for script_name in ("usb_setup.sh", "usb_setup.bat"):
        src = agent_dir / script_name
        if src.exists():
            content = src.read_text()
            content = content.replace("__BASE_URL__", base_url)
            content = content.replace("__FLEET_KEY__", fleet_key)
            # Rename for easier USB use
            dest_name = "setup.sh" if script_name.endswith(".sh") else "setup.bat"
            dest = out / dest_name
            dest.write_text(content)
            if dest_name.endswith(".sh"):
                os.chmod(dest, 0o755)

    # Create a README on the USB
    readme = f"""
╔══════════════════════════════════════════════════════════╗
║          NETWORK GUARDIAN — FIELD AGENT                  ║
║              WOLFPAK INTERNAL USE ONLY                   ║
╚══════════════════════════════════════════════════════════╝

This USB drive contains the Network Guardian field agent.
Only authorized Wolfpak team members can activate it.

SETUP INSTRUCTIONS:
───────────────────
  macOS / Linux:
    1. Open Terminal
    2. cd to this USB drive
    3. Run: bash setup.sh

  Windows:
    1. Double-click setup.bat
    2. If prompted, "Run as Administrator"

WHAT IT DOES:
─────────────
  • Scans WiFi networks for threats
  • Discovers devices on your network
  • Monitors system health (CPU, memory, disk)
  • Reports findings to the Wolfpak base station
  • Auto-starts every time you log in

REQUIRES:
─────────
  • Python 3.11 or newer
  • Internet connection to reach base station

TO UNINSTALL:
─────────────
  python3 ~/.ng_agent/probe.py --uninstall
  python3 ~/.ng_agent/probe.py --deauth

Base Station: {base_url}
Built: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}
"""
    (out / "README.txt").write_text(readme)

    print(f"\n  USB deployment package built: {out}/")
    print(f"  Contents:")
    for f in sorted(out.iterdir()):
        size = f.stat().st_size
        print(f"    {f.name:20s}  ({size:,} bytes)")
    print(f"\n  Copy the '{out.name}/' folder contents to a USB drive.")
    print(f"  Employee runs setup.sh (Mac/Linux) or setup.bat (Windows).")
    print(f"  Wolfpak credentials required on first launch.\n")
    return out


def build_agent(base_url: str, output_dir: str = "dist", agent_name: str = "ng-probe",
                one_file: bool = True, include_key: bool = True) -> Path:
    """Build the agent executable with PyInstaller."""
    probe_path = Path(__file__).parent / "probe.py"
    if not probe_path.exists():
        print(f"ERROR: probe.py not found at {probe_path}")
        sys.exit(1)

    # Check PyInstaller
    try:
        subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                       capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: PyInstaller not installed. Run: pip install pyinstaller")
        sys.exit(1)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Build wrapper that embeds the base URL
    wrapper = out / "_probe_wrapper.py"
    fleet_key = get_fleet_key(base_url) if include_key else ""

    wrapper_code = f'''#!/usr/bin/env python3
"""Auto-configured Network Guardian Field Agent."""
import sys
import os

# Embedded configuration
DEFAULT_BASE = {base_url!r}
DEFAULT_KEY = {fleet_key!r}

# Inject defaults if not provided via CLI
args = sys.argv[1:]
has_base = any(a.startswith("--base") for a in args)
has_key = any(a.startswith("--key") for a in args)

if not has_base and DEFAULT_BASE:
    args = ["--base", DEFAULT_BASE] + args
if not has_key and DEFAULT_KEY:
    args = ["--key", DEFAULT_KEY] + args

sys.argv = [sys.argv[0]] + args

# Import and run the probe
from network_guardian.agent.probe import main
main()
'''
    wrapper.write_text(wrapper_code)

    # PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", agent_name,
        "--clean",
        "--noconfirm",
        "--distpath", str(out),
        "--workpath", str(out / "build"),
        "--specpath", str(out),
    ]
    if one_file:
        cmd.append("--onefile")

    # Add hidden imports for the probe module
    cmd.extend([
        "--hidden-import", "network_guardian.agent",
        "--hidden-import", "network_guardian.agent.probe",
    ])

    # Add the probe source as data
    probe_dir = Path(__file__).parent
    cmd.extend(["--add-data", f"{probe_dir}{os.pathsep}network_guardian/agent"])

    cmd.append(str(wrapper))

    print(f"\n  Building {agent_name}...")
    print(f"  Base station: {base_url}")
    print(f"  Fleet key: {'embedded' if fleet_key else 'not embedded (provide via --key)'}")
    print(f"  Output: {out / agent_name}\n")

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print("ERROR: PyInstaller build failed")
        sys.exit(1)

    # Clean up
    wrapper.unlink(missing_ok=True)
    shutil.rmtree(out / "build", ignore_errors=True)
    spec_file = out / f"{agent_name}.spec"
    spec_file.unlink(missing_ok=True)

    exe_path = out / agent_name
    if sys.platform == "win32":
        exe_path = out / f"{agent_name}.exe"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n  SUCCESS: {exe_path} ({size_mb:.1f} MB)")
        print(f"\n  Copy to USB and run:")
        if fleet_key:
            print(f"    ./{agent_name}")
        else:
            print(f"    ./{agent_name} --base {base_url} --key <FLEET_KEY>")
        print(f"    ./{agent_name} --once          # single scan, no loop")
        print(f"    ./{agent_name} --interval 30   # report every 30s")
        return exe_path
    else:
        print("WARNING: Executable not found at expected path. Check dist/ folder.")
        return out


def main():
    parser = argparse.ArgumentParser(
        prog="ng-build-agent",
        description="Build Network Guardian field agent for USB deployment (Wolfpak only)",
    )
    parser.add_argument("--base", required=True,
                        help="Base station URL to embed (e.g. http://192.168.1.100:8080)")
    parser.add_argument("--output", default="dist",
                        help="Output directory (default: dist)")
    parser.add_argument("--name", default="ng-probe",
                        help="Name of the executable (default: ng-probe)")
    parser.add_argument("--no-key", action="store_true",
                        help="Don't embed fleet key (agent must provide via --key)")
    parser.add_argument("--dir-mode", action="store_true",
                        help="Build as directory instead of single file (faster startup)")
    parser.add_argument("--exe", action="store_true",
                        help="Build standalone executable with PyInstaller (requires pyinstaller)")
    parser.add_argument("--interval", type=int, default=60,
                        help="Default report interval in seconds (default: 60)")

    args = parser.parse_args()

    fleet_key = get_fleet_key(args.base)

    if args.exe:
        # PyInstaller executable build
        build_agent(
            base_url=args.base,
            output_dir=args.output,
            agent_name=args.name,
            one_file=not args.dir_mode,
            include_key=not args.no_key,
        )
    else:
        # Default: USB deployment package (no PyInstaller needed)
        build_usb_package(
            base_url=args.base,
            fleet_key=fleet_key,
            output_dir=os.path.join(args.output, "usb_deploy"),
            interval=args.interval,
        )


if __name__ == "__main__":
    main()
