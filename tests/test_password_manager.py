"""Tests for password_manager.py — vault and team integration."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from password_manager import (
    PasswordManager,
    _hash_password,
    _verify_password,
)


# ---------------------------------------------------------------------------
# Hashing primitives
# ---------------------------------------------------------------------------

class TestHashing:
    def test_hash_returns_hex_and_salt(self):
        pw_hash, salt = _hash_password("secret123")
        assert len(pw_hash) == 64     # SHA-256 hex digest
        assert len(salt) == 32        # 16-byte salt as hex

    def test_hash_is_deterministic_with_same_salt(self):
        _, salt = _hash_password("secret123")
        h1, _ = _hash_password("secret123", salt=salt)
        h2, _ = _hash_password("secret123", salt=salt)
        assert h1 == h2

    def test_different_salts_produce_different_hashes(self):
        h1, _ = _hash_password("secret123")
        h2, _ = _hash_password("secret123")
        assert h1 != h2

    def test_verify_correct_password(self):
        pw_hash, salt = _hash_password("correct")
        assert _verify_password("correct", pw_hash, salt) is True

    def test_verify_wrong_password(self):
        pw_hash, salt = _hash_password("correct")
        assert _verify_password("wrong", pw_hash, salt) is False


# ---------------------------------------------------------------------------
# PasswordManager — vault operations
# ---------------------------------------------------------------------------

class TestPasswordManager:
    def test_add_and_verify(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        pm.add_password("github", "mysecret")
        entry = pm.passwords["github"]
        assert entry["generated"] is False
        assert entry["plaintext"] is None
        assert _verify_password("mysecret", entry["hash"], entry["salt"])

    def test_persistence(self, tmp_path):
        vault = tmp_path / "vault.json"
        pm = PasswordManager(vault_path=vault)
        pm.add_password("github", "mysecret")

        # Re-load from disk
        pm2 = PasswordManager(vault_path=vault)
        assert "github" in pm2.passwords

    def test_generate_password_returns_plaintext(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        generated = pm.generate_password("jira")
        assert isinstance(generated, str)
        assert len(generated) > 10
        assert pm.passwords["jira"]["generated"] is True
        assert pm.passwords["jira"]["plaintext"] == generated

    def test_generated_password_is_valid(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        generated = pm.generate_password("service")
        entry = pm.passwords["service"]
        assert _verify_password(generated, entry["hash"], entry["salt"])

    def test_get_password_unknown_user(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        assert pm.get_password("nobody") is False

    def test_get_password_correct(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        pm.add_password("alice", "hunter2")
        with patch("getpass.getpass", return_value="hunter2"):
            assert pm.get_password("alice") is True

    def test_get_password_incorrect(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        pm.add_password("alice", "hunter2")
        with patch("getpass.getpass", return_value="wrong"):
            assert pm.get_password("alice") is False

    def test_overwrite_entry(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        pm.add_password("svc", "old")
        pm.add_password("svc", "new")
        assert _verify_password("new", pm.passwords["svc"]["hash"], pm.passwords["svc"]["salt"])
        assert not _verify_password("old", pm.passwords["svc"]["hash"], pm.passwords["svc"]["salt"])

    def test_show_passwords_empty(self, tmp_path, capsys):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        pm.show_passwords()
        assert "empty" in capsys.readouterr().out.lower()

    def test_show_passwords_redacts_manual(self, tmp_path, capsys):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        pm.add_password("bob", "s3cr3t")
        pm.show_passwords()
        out = capsys.readouterr().out
        assert "REDACTED" in out
        assert "s3cr3t" not in out

    def test_show_passwords_shows_generated(self, tmp_path, capsys):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        generated = pm.generate_password("svc")
        pm.show_passwords()
        out = capsys.readouterr().out
        assert generated in out

    def test_vault_file_is_valid_json(self, tmp_path):
        pm = PasswordManager(vault_path=tmp_path / "vault.json")
        pm.add_password("x", "y")
        data = json.loads((tmp_path / "vault.json").read_text())
        assert "x" in data
        assert "hash" in data["x"]
        assert "salt" in data["x"]

    def test_corrupted_vault_resets_gracefully(self, tmp_path):
        vault = tmp_path / "vault.json"
        vault.write_text("{invalid json")
        pm = PasswordManager(vault_path=vault)
        assert pm.passwords == {}
