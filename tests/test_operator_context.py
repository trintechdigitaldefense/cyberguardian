from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))
from operator_context import AssertionError, mint_assertion, verify_assertion


SECRET = "test-only-secret-that-is-at-least-32-bytes"


def token(**overrides):
    values = dict(
        secret=SECRET, subject="operator-17", role="operator", tenant_id="tenant-a",
        method="POST", path="/v1/gate/approve/act-1", request_id="req-123", now=1000,
    )
    values.update(overrides)
    return mint_assertion(**values)


def verify(value, tmp_path, **overrides):
    params = dict(
        secret=SECRET, method="POST", path="/v1/gate/approve/act-1",
        tenant_id="tenant-a", replay_db=tmp_path / "replay.sqlite3", now=1001,
    )
    params.update(overrides)
    return verify_assertion(value, **params)


def test_valid_assertion_returns_verified_operator_claims(tmp_path):
    claims = verify(token(), tmp_path)
    assert claims["sub"] == "operator-17"
    assert claims["role"] == "operator"
    assert claims["tenant_id"] == "tenant-a"
    assert claims["request_id"] == "req-123"


def test_assertion_nonce_is_single_use_across_verifications(tmp_path):
    value = token()
    verify(value, tmp_path)
    try:
        verify(value, tmp_path)
    except AssertionError as exc:
        assert "replay" in str(exc)
    else:
        raise AssertionError("replayed assertion must be rejected")


def test_assertion_rejects_tampering_and_request_binding_mismatch(tmp_path):
    value = token()
    encoded, signature = value.split(".", 1)
    tampered = encoded[:-2] + ("aa" if encoded[-2:] != "aa" else "bb") + "." + signature
    for candidate, overrides in (
        (tampered, {}),
        (value, {"method": "GET"}),
        (value, {"path": "/v1/gate/reject/act-1"}),
        (value, {"tenant_id": "tenant-b"}),
    ):
        try:
            verify(candidate, tmp_path, **overrides)
        except AssertionError:
            pass
        else:
            raise AssertionError("invalid assertion must be rejected")


def test_assertion_rejects_expired_and_future_dated_claims(tmp_path):
    for issued in (900, 1100):
        value = token(now=issued)
        try:
            verify(value, tmp_path, now=1001)
        except AssertionError as exc:
            assert "expired" in str(exc) or "valid" in str(exc)
        else:
            raise AssertionError("out-of-window assertion must be rejected")


def test_short_signing_secret_is_rejected():
    try:
        token(secret="too-short")
    except AssertionError as exc:
        assert "32 bytes" in str(exc)
    else:
        raise AssertionError("weak signing secret must be rejected")



def test_dashboard_mints_assertion_from_server_session(tmp_path, monkeypatch):
    dashboard_dir = Path(__file__).resolve().parents[1] / "dashboard"
    sys.path.insert(0, str(dashboard_dir))
    try:
        spec = importlib.util.spec_from_file_location("cg_operator_dashboard_test", dashboard_dir / "main.py")
        dashboard = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = dashboard
        spec.loader.exec_module(dashboard)
    finally:
        sys.path.remove(str(dashboard_dir))
    monkeypatch.setattr(dashboard.dashboard_auth, "PRODUCTION", False)
    monkeypatch.setenv("CG_OPERATOR_ASSERTION_SECRET", SECRET)
    session = {"username": "alice", "role": "admin", "tenant_id": "tenant-z"}
    headers = dashboard.operator_headers(session, "POST", "/v1/gate/approve/abc", "tenant-z")
    assert headers["X-API-Key"] == dashboard.API_KEY
    assert headers["X-Tenant-ID"] == "tenant-z"
    assert headers["X-Request-ID"]
    claims = verify_assertion(
        headers["X-CG-Operator-Assertion"],
        secret=SECRET,
        method="POST",
        path="/v1/gate/approve/abc",
        tenant_id="tenant-z",
        replay_db=tmp_path / "dashboard-replay.sqlite3",
    )
    assert claims["sub"] == "alice"
    assert claims["role"] == "admin"
