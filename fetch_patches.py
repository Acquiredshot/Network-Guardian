#!/usr/bin/env python3
"""
Fetch recommended patches and fixes from the centralized dashboard
"""

import json
import sys
import requests
from pathlib import Path
from datetime import datetime

def _session_login(base_url: str, username: str, password: str):
    """Authenticate via dashboard session API and return a requests Session or None."""
    session = requests.Session()
    try:
        resp = session.post(
            f"{base_url}/api/auth/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"},
            timeout=10,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                return session
    except Exception:
        pass
    return None


def _save_patches_locally(patches: list[dict], source: str) -> Path:
    patches_dir = Path.home() / ".network_guardian" / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    patches_file = patches_dir / "pending_patches.json"
    with open(patches_file, "w") as f:
        json.dump(
            {
                "fetched_at": datetime.now().isoformat(),
                "source": source,
                "patches": patches,
            },
            f,
            indent=2,
        )
    return patches_file


def _display_patches(patches: list[dict]):
    print(f"\n{'='*70}")
    print(f"  RECOMMENDED PATCHES ({len(patches)} available)")
    print(f"{'='*70}\n")

    if not patches:
        print("✅ No patches needed - system up to date!\n")
        return

    by_severity = {}
    for patch in patches:
        severity = patch.get("severity", "medium")
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(patch)

    severity_order = ["critical", "high", "medium", "low"]
    for severity in severity_order:
        if severity in by_severity:
            patches_for_sev = by_severity[severity]
            print(f"[{severity.upper()}] {len(patches_for_sev)} patch(es)\n")
            for patch in patches_for_sev:
                print(f"  • {patch.get('title', 'Patch recommendation')}")
                print(f"    Description: {patch.get('description', 'N/A')}")
                if patch.get('cve_id'):
                    print(f"    CVE: {patch['cve_id']}")
                if patch.get('command'):
                    print("    Fix command:")
                    print(f"    $ {patch['command']}")
                print()

    print(f"{'='*70}\n")


def _fallback_patch_config(agent_id: str):
    """Read base-pushed patch_config from local fleet store when /api/patches is unavailable."""
    fleet_file = Path.home() / ".network_guardian" / "fleet.json"
    if not fleet_file.exists():
        return []
    try:
        data = json.loads(fleet_file.read_text())
        agent = data.get("agents", {}).get(agent_id, {})
        cfg = agent.get("pending_patch_config")
        if not cfg:
            return []
        return [
            {
                "id": f"PATCHCFG-{agent_id}",
                "title": "Base-pushed probe patch configuration",
                "description": f"Apply runtime patch_config for {agent_id}: {cfg}",
                "severity": "high",
                "category": "configuration",
                "command": "Delivered automatically on next probe phone-home",
            }
        ]
    except Exception:
        return []


def fetch_patches(dashboard_url: str, agent_id: str, username: str, password: str):
    """Fetch available patches from dashboard."""
    try:
        # Construct API endpoint
        patches_url = f"{dashboard_url}/api/patches"

        # Attempt legacy/basic auth first for backward compatibility.
        response = requests.get(
            patches_url,
            params={"agent_id": agent_id},
            auth=(username, password),
            timeout=10,
            verify=False,
        )

        if response.status_code in (401, 403):
            # Fallback to current session auth flow.
            session = _session_login(dashboard_url, username, password)
            if session is not None:
                response = session.get(
                    patches_url,
                    params={"agent_id": agent_id},
                    timeout=10,
                    verify=False,
                )

        if response.status_code == 200:
            data = response.json()
            patches = data.get("patches", [])
            _display_patches(patches)
            patches_file = _save_patches_locally(patches, source="/api/patches")
            print(f"✓ Patches saved to: {patches_file}\n")
            return

        # New runtime fallback: local fleet patch_config queue.
        if response.status_code in (404, 401, 403):
            cfg_patches = _fallback_patch_config(agent_id)
            if cfg_patches:
                print("ℹ️ /api/patches unavailable or unauthorized; using local fleet patch_config fallback.\n")
                _display_patches(cfg_patches)
                patches_file = _save_patches_locally(cfg_patches, source="fleet.pending_patch_config")
                print(f"✓ Fallback patches saved to: {patches_file}\n")
                return
            print("ℹ️ /api/patches unavailable and no pending fleet patch_config for this agent.")
            _display_patches([])
            patches_file = _save_patches_locally([], source="none")
            print(f"✓ Patch state saved to: {patches_file}\n")
            return

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
