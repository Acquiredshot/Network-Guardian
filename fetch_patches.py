#!/usr/bin/env python3
"""
Fetch recommended patches and fixes from the centralized dashboard
"""

import json
import sys
import requests
from pathlib import Path
from datetime import datetime

def fetch_patches(dashboard_url: str, agent_id: str, username: str, password: str):
    """Fetch available patches from dashboard."""
    try:
        # Construct API endpoint
        patches_url = f"{dashboard_url}/api/patches"

        # Authenticate with dashboard
        auth = (username, password)

        # Fetch patches
        response = requests.get(
            patches_url,
            params={"agent_id": agent_id},
            auth=auth,
            timeout=10,
            verify=False  # Local testing
        )

        if response.status_code == 200:
            data = response.json()
            patches = data.get("patches", [])
            print(f"\n{'='*70}")
            print(f"  RECOMMENDED PATCHES ({len(patches)} available)")
            print(f"{'='*70}\n")

            if not patches:
                print("✅ No patches needed - system up to date!\n")
                return

            # Group by severity
            by_severity = {}
            for patch in patches:
                severity = patch.get("severity", "medium")
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(patch)

            # Display by severity
            severity_order = ["critical", "high", "medium", "low"]
            for severity in severity_order:
                if severity in by_severity:
                    patches_for_sev = by_severity[severity]
                    print(f"[{severity.upper()}] {len(patches_for_sev)} patch(es)\n")
                    for patch in patches_for_sev:
                        print(f"  • {patch['title']}")
                        print(f"    Description: {patch['description']}")
                        if patch.get('cve_id'):
                            print(f"    CVE: {patch['cve_id']}")
                        if patch.get('command'):
                            print(f"    Fix command:")
                            print(f"    $ {patch['command']}")
                        print()

            print(f"{'='*70}\n")

            # Save patches locally
            patches_dir = Path.home() / ".network_guardian" / "patches"
            patches_dir.mkdir(parents=True, exist_ok=True)

            patches_file = patches_dir / "pending_patches.json"
            with open(patches_file, "w") as f:
                json.dump({
                    "fetched_at": datetime.now().isoformat(),
                    "patches": patches
                }, f, indent=2)

            print(f"✓ Patches saved to: {patches_file}\n")

        else:
            print(f"❌ Failed to fetch patches: HTTP {response.status_code}")

    except Exception as e:
        print(f"❌ Error fetching patches: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Get parameters
    dashboard_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    agent_id = sys.argv[2] if len(sys.argv) > 2 else "NG-LOCAL"
    username = sys.argv[3] if len(sys.argv) > 3 else "admin"
    password = sys.argv[4] if len(sys.argv) > 4 else "<password>"

    fetch_patches(dashboard_url, agent_id, username, password)
