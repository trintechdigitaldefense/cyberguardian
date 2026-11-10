from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH_PATH = ROOT / "dashboard" / "auth.py"
spec = importlib.util.spec_from_file_location("cg_dashboard_auth_tests", AUTH_PATH)
auth = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = auth
spec.loader.exec_module(auth)


def configure_store(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DATA_DIR", tmp_path)
    monkeypatch.setattr(auth, "CREDS_PATH", tmp_path / "credentials.json")
    monkeypatch.setattr(auth, "AUTH_DB", tmp_path / "dashboard_auth.sqlite3")
    auth.init_auth_store()


def test_password_hash_is_salted_and_verifies(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    first = auth.hash_password("correct horse battery staple")
    second = auth.hash_password("correct horse battery staple")
    assert first != second
    assert auth.verify_password("correct horse battery staple", first)
    assert not auth.verify_password("wrong password", first)
    assert "correct horse battery staple" not in first


def test_persistent_session_csrf_expiry_and_revocation(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    user = {"username": "admin", "tenant_id": "tenant-a", "role": "admin"}
    token, csrf, expires = auth.create_session(user, now=1000)
    stored = auth.get_session(token, now=1001)
    assert stored["username"] == "admin"
    assert stored["tenant_id"] == "tenant-a"
    assert auth.verify_csrf(stored, csrf)
    assert not auth.verify_csrf(stored, "wrong")
    assert auth.get_session(token, now=expires + 1) is None
    assert auth.revoke_session(token)
    assert auth.get_session(token, now=1001) is None


def test_login_rate_limit_persists_and_expires(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "MAX_LOGIN_FAILURES", 3)
    monkeypatch.setattr(auth, "LOGIN_WINDOW_SECONDS", 100)
    for timestamp in (100, 101, 102):
        auth.record_login_attempt("192.0.2.4", "admin", False, now=timestamp)
    assert auth.is_rate_limited("192.0.2.4", "admin", now=150)
    assert not auth.is_rate_limited("192.0.2.4", "admin", now=250)



def test_login_throttle_covers_ip_and_account_across_distinct_pairs(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "MAX_LOGIN_FAILURES", 3)
    monkeypatch.setattr(auth, "LOGIN_WINDOW_SECONDS", 1000)
    for index in range(15):
        auth.record_login_attempt("192.0.2.50", f"unknown-{index}", False, now=100 + index)
    assert auth.is_rate_limited("192.0.2.50", "another-username", now=120)

    configure_store(tmp_path / "account-scope", monkeypatch)
    for index in range(12):
        auth.record_login_attempt(f"198.51.100.{index + 1}", "admin", False, now=200 + index)
    assert auth.is_rate_limited("203.0.113.99", "admin", now=220)

def test_hashed_credentials_authenticate_in_production(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "PRODUCTION", True)
    encoded = auth.hash_password("production password 123")
    auth.CREDS_PATH.write_text(json.dumps({
        "admin_user": "admin",
        "admin_password_hash": encoded,
    }))
    assert auth.authenticate_user("admin", "production password 123")["role"] == "admin"
    assert auth.authenticate_user("admin", "wrong password") is None


def test_production_refuses_legacy_plaintext_password(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "PRODUCTION", True)
    auth.CREDS_PATH.write_text(json.dumps({
        "admin_user": "admin",
        "admin_password": "legacy plaintext password",
    }))
    assert auth.authenticate_user("admin", "legacy plaintext password") is None


def test_development_login_migrates_legacy_plaintext_file(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "PRODUCTION", False)
    auth.CREDS_PATH.write_text(json.dumps({
        "admin_user": "admin",
        "admin_password": "legacy plaintext password",
        "api_key": "preserve-this-api-key",
    }))
    assert auth.authenticate_user("admin", "legacy plaintext password")
    migrated = json.loads(auth.CREDS_PATH.read_text())
    assert "admin_password" not in migrated
    assert auth.verify_password("legacy plaintext password", migrated["admin_password_hash"])
    assert migrated["api_key"] == "preserve-this-api-key"


def test_user_registry_enforces_tenant_and_role(tmp_path, monkeypatch):
    configure_store(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "PRODUCTION", True)
    auth.CREDS_PATH.write_text(json.dumps({
        "users": {
            "viewer-1": {
                "password_hash": auth.hash_password("viewer password 123"),
                "tenant_id": "customer-7",
                "role": "viewer",
            }
        }
    }))
    user = auth.authenticate_user("viewer-1", "viewer password 123")
    assert user["tenant_id"] == "customer-7"
    assert user["role"] == "viewer"



def test_dashboard_uses_external_assets_and_escapes_dynamic_values():
    dashboard = Path(__file__).resolve().parents[1] / "dashboard"
    index_html = (dashboard / "templates" / "index.html").read_text(encoding="utf-8")
    login_html = (dashboard / "templates" / "login.html").read_text(encoding="utf-8")
    script = (dashboard / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "<script>" not in index_html and "<style>" not in index_html
    assert "onclick=" not in index_html and 'style="' not in index_html
    assert "<script>" not in login_html and "<style>" not in login_html
    assert "/static/dashboard.js" in index_html
    assert "/static/dashboard.css" in index_html
    assert "/static/login.css" in login_html
    assert ".replace(/</g,'&lt;')" in script
    assert ".replace(/'/g,'&#39;')" in script
