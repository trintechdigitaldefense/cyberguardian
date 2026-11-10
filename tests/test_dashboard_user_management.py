from __future__ import annotations

import json
import sys
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))
import auth
from user_admin import upsert_user


def test_dashboard_user_provisioning_hashes_password_and_scopes_tenant(tmp_path, monkeypatch):
    credentials_path = tmp_path / "credentials.json"
    monkeypatch.setattr(auth, "CREDS_PATH", credentials_path)
    user = upsert_user(
        username="ops-alice",
        tenant_id="tenant-a",
        role="operator",
        password="Long-Unique-Password-2026!",
    )
    assert user == {"username": "ops-alice", "tenant_id": "tenant-a", "role": "operator"}
    record = json.loads(credentials_path.read_text(encoding="utf-8"))
    saved = record["users"]["ops-alice"]
    assert saved["password_hash"].startswith("pbkdf2_sha256$")
    assert "Long-Unique-Password-2026!" not in credentials_path.read_text(encoding="utf-8")
    assert auth.authenticate_user("ops-alice", "Long-Unique-Password-2026!") == {
        "username": "ops-alice",
        "password_hash": saved["password_hash"],
        "legacy_password": "",
        "tenant_id": "tenant-a",
        "role": "operator",
    }
    assert credentials_path.stat().st_mode & 0o777 == 0o600


def test_dashboard_user_provisioning_rejects_duplicate_and_invalid_role(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "CREDS_PATH", tmp_path / "credentials.json")
    upsert_user(
        username="ops-bob", tenant_id="tenant-b", role="viewer",
        password="Another-Long-Password-2026!",
    )
    try:
        upsert_user(
            username="ops-bob", tenant_id="tenant-b", role="viewer",
            password="Another-Long-Password-2026!",
        )
    except ValueError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("duplicate user must be rejected")
    try:
        upsert_user(
            username="ops-evil", tenant_id="tenant-b", role="superadmin",
            password="Another-Long-Password-2026!",
        )
    except ValueError as exc:
        assert "role" in str(exc)
    else:
        raise AssertionError("unsupported role must be rejected")
