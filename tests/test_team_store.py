from network_guardian.interface._security import TeamStore


def test_team_store_ensure_default_admin_resets_stale_admin(tmp_path):
    store = TeamStore(tmp_path)
    store.add_member("admin", "Admin", "OldPass!", role="admin")

    reset_password = store.ensure_default_admin("admin", "Admin", "Admin123!")

    assert reset_password == "Admin123!"
    assert store.authenticate("admin", "Admin123!") is not None
    assert store.authenticate("admin", "OldPass!") is None
