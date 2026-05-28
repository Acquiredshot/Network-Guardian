"""
Password Vault — Network Guardian

Stores and manages credentials for external services/accounts.
Uses the same PBKDF2-HMAC-SHA256 hashing as network_guardian.interface._security
so the entire codebase shares one hashing approach.

Vault is persisted to password_vault.json (separate from wolfpak_team.json).
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import secrets
from pathlib import Path

_VAULT_FILE = Path(__file__).parent / "password_vault.json"
_PBKDF2_ITERATIONS = 260_000


def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password with PBKDF2-HMAC-SHA256. Returns (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return h.hex(), salt


def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Constant-time compare against stored PBKDF2 hash."""
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return hmac.compare_digest(h.hex(), stored_hash)


class PasswordManager:
    """Credential vault — persisted to password_vault.json.

    Entry schema::

        {
          "hash": "<hex>",
          "salt": "<hex>",
          "generated": true|false,
          "plaintext": "<str>|null"   # only set for generated passwords
        }
    """

    def __init__(self, vault_path: Path = _VAULT_FILE):
        self._path = vault_path
        self.passwords: dict = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path, "r") as f:
                    self.passwords = json.load(f)
            except (json.JSONDecodeError, OSError):
                self.passwords = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self.passwords, f, indent=2)
        tmp.replace(self._path)

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def add_password(self, username: str, password: str) -> None:
        pw_hash, salt = _hash_password(password)
        self.passwords[username] = {
            "hash": pw_hash,
            "salt": salt,
            "generated": False,
            "plaintext": None,
        }
        self._save()

    def get_password(self, username: str) -> bool:
        """Prompt the user to verify their stored password. Returns True if correct."""
        if username not in self.passwords:
            return False
        entry = self.passwords[username]
        provided = getpass.getpass(f"Enter your {username} password: ")
        return _verify_password(provided, entry["hash"], entry["salt"])

    def generate_password(self, username: str) -> str:
        """Generate a strong random password, store it, and return the plaintext."""
        generated = secrets.token_urlsafe(16)
        pw_hash, salt = _hash_password(generated)
        self.passwords[username] = {
            "hash": pw_hash,
            "salt": salt,
            "generated": True,
            "plaintext": generated,
        }
        self._save()
        return generated

    def show_passwords(self) -> None:
        if not self.passwords:
            print("Vault is empty.")
            return
        for username, info in self.passwords.items():
            if info.get("generated") and info.get("plaintext"):
                print(f"Username: {username}, Password: {info['plaintext']} (generated)")
            else:
                print(f"Username: {username}, Password: [REDACTED]")


def main():
    from network_guardian.interface._security import TeamStore

    _TEAM_DATA_DIR = Path.home() / ".network_guardian"
    pm = PasswordManager()
    team = TeamStore(_TEAM_DATA_DIR)

    while True:
        print("\n--- Credential Vault (external accounts) ---")
        print("1. Add a vault entry")
        print("2. Verify a vault password")
        print("3. Generate & store a vault password")
        print("4. List vault entries")
        print("\n--- Team User Accounts (wolfpak_team.json) ---")
        print("5. Add a team user")
        print("6. Change a team user's password")
        print("7. List team users")
        print("8. Remove a team user")
        choice = input("\nChoose an option (or 'q' to quit): ").strip()

        if choice == "1":
            username = input("Enter the account label: ")
            password = getpass.getpass("Enter the password: ")
            pm.add_password(username, password)
            print(f"Vault entry stored for '{username}'.")

        elif choice == "2":
            username = input("Enter the account label: ")
            if pm.get_password(username):
                print(f"Password verified for '{username}'.")
            else:
                print("Incorrect password or label not found.")

        elif choice == "3":
            username = input("Enter the account label: ")
            generated = pm.generate_password(username)
            print(f"Generated password for '{username}': {generated}")

        elif choice == "4":
            pm.show_passwords()

        elif choice == "5":
            username = input("Team username: ").strip().lower()
            display_name = input("Display name (Enter to skip): ").strip() or username
            role = input("Role (operator/admin) [operator]: ").strip() or "operator"
            password = getpass.getpass("Password: ")
            try:
                team.add_member(username, display_name, password, role=role)
                print(f"Team user '{username}' added.")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "6":
            username = input("Team username: ").strip().lower()
            new_password = getpass.getpass("New password: ")
            try:
                if team.change_password(username, new_password):
                    print(f"Password updated for '{username}'.")
                else:
                    print(f"User '{username}' not found.")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "7":
            members = team.list_members()
            if not members:
                print("No team members found.")
            else:
                print(f"\n{'Username':<20} {'Role':<10} {'Active':<8} {'Expires In'}")
                print("-" * 55)
                for m in members:
                    expiry = f"{m['days_until_expiry']}d" if not m['expired'] else "EXPIRED"
                    print(f"{m['username']:<20} {m['role']:<10} {str(m['active']):<8} {expiry}")

        elif choice == "8":
            username = input("Team username to remove: ").strip().lower()
            confirm = input(f"Remove '{username}'? This cannot be undone. (yes/no): ")
            if confirm.lower() == "yes":
                if team.remove_member(username):
                    print(f"Team user '{username}' removed.")
                else:
                    print(f"User '{username}' not found.")
            else:
                print("Cancelled.")

        elif choice.lower() == "q":
            break
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
