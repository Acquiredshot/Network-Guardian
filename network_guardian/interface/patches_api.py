"""
Patch & Recommendation Delivery API

Serves recommended security patches and system fixes to remote probes.
Probes fetch this data via /api/patches endpoint.
"""

from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from network_guardian.core.engine import Engine

logger = logging.getLogger("network_guardian.interface.patches_api")


class PatchStore:
    """Manages recommended patches and fixes for distribution."""

    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or Path.home() / ".network_guardian"
        self.patches_file = self.data_dir / "patches" / "recommended_patches.json"
        self.patches_file.parent.mkdir(parents=True, exist_ok=True)
        self._patches = []
        self._load_patches()

    def _load_patches(self) -> None:
        """Load patches from disk."""
        if not self.patches_file.exists():
            return
        try:
            with open(self.patches_file) as f:
                self._patches = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load patches: {e}")

    def _save_patches(self) -> None:
        """Persist patches to disk."""
        try:
            with open(self.patches_file, "w") as f:
                json.dump(self._patches, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save patches: {e}")

    def add_patch(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        category: str = "security",
        affected_systems: list[str] | None = None,
        cve_id: str | None = None,
        command: str | None = None,
    ) -> dict[str, Any]:
        """Add a new patch recommendation."""
        patch = {
            "id": f"PATCH-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "title": title,
            "description": description,
            "severity": severity,
            "category": category,
            "affected_systems": affected_systems or [],
            "cve_id": cve_id,
            "command": command,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }
        self._patches.append(patch)
        self._save_patches()
        logger.info(f"Added patch: {patch['id']} - {title}")
        return patch

    def get_patches(self, agent_id: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Get all pending patches or filter by agent."""
        patches = [p for p in self._patches if p.get("status") == "pending"]
        if agent_id and "affected_systems" in patches[0] if patches else False:
            patches = [p for p in patches if not p["affected_systems"] or agent_id in p["affected_systems"]]
        if limit:
            patches = patches[:limit]
        return patches

    def mark_applied(self, patch_id: str, agent_id: str) -> None:
        """Mark a patch as applied on an agent."""
        for patch in self._patches:
            if patch["id"] == patch_id:
                patch["status"] = "applied"
                patch["applied_at"] = datetime.now(timezone.utc).isoformat()
                patch["applied_on"] = agent_id
                self._save_patches()
                logger.info(f"Marked {patch_id} as applied on {agent_id}")
                return


class PatchesAPI:
    """HTTP API for patch delivery."""

    def __init__(self, engine: Engine | None = None):
        self.engine = engine
        self.store = PatchStore()
        self._bootstrap_default_patches()

    def _bootstrap_default_patches(self) -> None:
        """Initialize with common security patches."""
        if len(self.store._patches) > 0:
            return

        patches = [
            {
                "title": "Update OpenSSL to 1.1.1 or later",
                "description": "Critical: TLS 1.0 and TLS 1.1 vulnerabilities (CVE-2021-41117)",
                "severity": "critical",
                "category": "cryptography",
                "cve_id": "CVE-2021-41117",
                "command": "brew upgrade openssl",
            },
            {
                "title": "Disable SSH password authentication",
                "description": "High: SSH brute force exposure - enforce key-based auth only",
                "severity": "high",
                "category": "authentication",
                "command": "sudo sed -i '' 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
            },
            {
                "title": "Enable UFW firewall",
                "description": "High: No active host firewall - enable UFW for inbound filtering",
                "severity": "high",
                "category": "firewall",
                "command": "sudo ufw enable",
            },
            {
                "title": "Disable Telnet and FTP services",
                "description": "High: Plaintext protocols detected - use SSH and SFTP instead",
                "severity": "high",
                "category": "network",
                "command": "sudo systemctl disable telnetd && sudo systemctl disable vsftpd",
            },
            {
                "title": "Update system packages",
                "description": "Medium: Security patches available from package repository",
                "severity": "medium",
                "category": "updates",
                "command": "sudo apt update && sudo apt upgrade -y",
            },
            {
                "title": "Enable automatic security updates",
                "description": "Medium: Automatic patching not enabled - turn on unattended upgrades",
                "severity": "medium",
                "category": "updates",
                "command": "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
            },
        ]

        for p in patches:
            self.store.add_patch(
                title=p["title"],
                description=p["description"],
                severity=p.get("severity", "medium"),
                category=p.get("category", "security"),
                cve_id=p.get("cve_id"),
                command=p.get("command"),
            )

    async def get_patches_handler(self, agent_id: str | None = None) -> dict[str, Any]:
        """HTTP GET /api/patches - Return patches for an agent."""
        patches = self.store.get_patches(agent_id=agent_id, limit=20)
        return {
            "status": "ok",
            "agent_id": agent_id,
            "patch_count": len(patches),
            "patches": patches,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def apply_patch_handler(self, patch_id: str, agent_id: str) -> dict[str, Any]:
        """HTTP POST /api/patches/{patch_id}/apply - Mark patch as applied."""
        self.store.mark_applied(patch_id, agent_id)
        return {
            "status": "applied",
            "patch_id": patch_id,
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
