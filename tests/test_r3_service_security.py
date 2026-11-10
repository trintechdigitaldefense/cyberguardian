from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "control-plane" / "api"
DECISION_DIR = ROOT / "control-plane" / "decision-service"
DASHBOARD_DIR = ROOT / "dashboard"
sys.path.insert(0, str(API_DIR))

from gateway_patches.decision_service_auth import patch_source as patch_decision_auth
from gateway_patches.cors_config import patch_source as patch_cors


def test_gateway_decision_service_patch_authenticates_all_calls():
    source = '''
import os
from fastapi import HTTPException
DECISION_URL = os.getenv("DECISION_SERVICE_URL", "http://127.0.0.1:8001")
async def one(client, detection):
    resp = await client.post(f"{DECISION_URL}/v1/decide", json=detection)
async def two(client, action):
    resp = await client.post(
        f"{DECISION_URL}/v1/execute",
        json=action,
    )
async def three(client, action):
    resp = await client.post(
        f"{DECISION_URL}/v1/execute",
        json=action,
    )
'''
    patched = patch_decision_auth(source)
    assert patched.count('headers=decision_service_headers()') == 3
    assert 'X-Decision-Service-Key' in patched
    assert "Decision-service authentication is not configured" in patched


def test_gateway_decision_service_patch_fails_on_source_drift():
    try:
        patch_decision_auth('DECISION_URL = "http://localhost"')
    except ValueError as exc:
        assert "decision-service URL anchor" in str(exc)
    else:
        raise AssertionError("patch must fail closed when gateway source drifts")


def test_gateway_cors_patch_uses_explicit_origin_list():
    source = '''app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)'''
    patched = patch_cors(source)
    assert 'allow_origins=_cors_origins' in patched
    assert 'allow_origins=["*"]' not in patched
    assert 'if not _cors_origins or "*" in _cors_origins' in patched


def test_gateway_cors_patch_fails_closed_on_source_drift():
    try:
        patch_cors('app.add_middleware(CORSMiddleware, allow_origins=["*"])')
    except ValueError as exc:
        assert "CORS middleware anchor" in str(exc)
    else:
        raise AssertionError("CORS patch must fail closed when source drifts")


def _load_decision_module():
    sys.path.insert(0, str(DECISION_DIR))
    try:
        spec = importlib.util.spec_from_file_location(
            "cg_decision_auth_test_module", DECISION_DIR / "main.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(DECISION_DIR))


def test_decision_service_rejects_missing_and_wrong_service_key(monkeypatch):
    from fastapi.testclient import TestClient

    decision = _load_decision_module()
    monkeypatch.setattr(decision, "PRODUCTION", True)
    monkeypatch.setattr(decision, "SERVICE_KEY", "a" * 40)
    client = TestClient(decision.app)
    assert client.get("/health").status_code == 200
    assert client.get("/v1/protection").status_code == 401
    assert client.get("/v1/protection", headers={"X-Decision-Service-Key": "wrong"}).status_code == 401
    assert client.get("/v1/protection", headers={"X-Decision-Service-Key": "a" * 40}).status_code == 200


def test_decision_service_fails_closed_when_production_key_missing(monkeypatch):
    from fastapi.testclient import TestClient

    decision = _load_decision_module()
    monkeypatch.setattr(decision, "PRODUCTION", True)
    monkeypatch.setattr(decision, "SERVICE_KEY", "")
    response = TestClient(decision.app).get("/v1/protection")
    assert response.status_code == 503


def test_dashboard_requires_csrf_and_enforces_roles(monkeypatch, tmp_path):
    from starlette.requests import Request
    sys.path.insert(0, str(DASHBOARD_DIR))
    try:
        dashboard_spec = importlib.util.spec_from_file_location(
            "cg_dashboard_r3_auth_test_module", DASHBOARD_DIR / "main.py"
        )
        dashboard = importlib.util.module_from_spec(dashboard_spec)
        sys.modules[dashboard_spec.name] = dashboard
        dashboard_spec.loader.exec_module(dashboard)
    finally:
        sys.path.remove(str(DASHBOARD_DIR))

    monkeypatch.setattr(dashboard.dashboard_auth, "AUTH_DB", tmp_path / "auth.sqlite3")
    monkeypatch.setattr(dashboard.dashboard_auth, "DATA_DIR", tmp_path)
    dashboard.dashboard_auth.init_auth_store()
    monkeypatch.setattr(dashboard, "SESSION_COOKIE", "test_session")
    monkeypatch.setattr(dashboard, "CSRF_COOKIE", "test_csrf")

    def request(method, cookies, csrf_header=None):
        cookie = "; ".join(f"{key}={value}" for key, value in cookies.items()).encode()
        headers = [(b"cookie", cookie)]
        if csrf_header:
            headers.append((b"x-csrf-token", csrf_header.encode()))
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": "/ops/client-mode",
            "raw_path": b"/ops/client-mode", "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345), "server": ("test", 80),
        }
        return Request(scope)

    admin = {"username": "admin", "tenant_id": "tenant-7", "role": "admin"}
    token, csrf, _ = dashboard.dashboard_auth.create_session(admin)
    assert dashboard._require_sess(request("POST", {"test_session": token})) .status_code == 403
    assert dashboard._require_sess(request("POST", {"test_session": token, "test_csrf": csrf}, csrf_header=csrf)) is None
    assert dashboard.tenant_for_request(request("GET", {"test_session": token})) == "tenant-7"
    assert dashboard.headers("tenant-7")["X-Tenant-ID"] == "tenant-7"

    from fastapi.testclient import TestClient
    login_password = "dashboard admin password 123"
    dashboard.dashboard_auth.CREDS_PATH = tmp_path / "credentials.json"
    dashboard.dashboard_auth.CREDS_PATH.write_text(json.dumps({
        "admin_user": "admin",
        "admin_password_hash": dashboard.dashboard_auth.hash_password(login_password),
    }))
    client = TestClient(dashboard.app, follow_redirects=False)
    login_page = client.get("/login")
    assert login_page.status_code == 200
    assert login_page.headers.get("cache-control") == "no-store"
    csp = login_page.headers.get("content-security-policy", "")
    assert "unsafe-inline" not in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert client.get("/static/login.css").status_code == 200
    assert client.get("/static/dashboard.js").status_code == 200
    login_token = re.search(r'name="login_csrf" value="([^"]+)"', login_page.text).group(1)
    invalid_login = client.post(
        "/login",
        data={"username": "admin", "password": login_password, "login_csrf": "wrong"},
    )
    assert invalid_login.status_code == 403
    successful_login = client.post(
        "/login",
        data={"username": "admin", "password": login_password, "login_csrf": login_token},
    )
    assert successful_login.status_code == 303
    session_token = client.cookies.get(dashboard.SESSION_COOKIE)
    csrf_token = client.cookies.get(dashboard.CSRF_COOKIE)
    assert dashboard.dashboard_auth.get_session(session_token)
    logout_without_csrf = client.post("/logout")
    assert logout_without_csrf.status_code == 403
    logout = client.post("/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout.status_code == 303
    assert dashboard.dashboard_auth.get_session(session_token) is None

    viewer = {"username": "viewer", "tenant_id": "tenant-8", "role": "viewer"}
    viewer_token, viewer_csrf, _ = dashboard.dashboard_auth.create_session(viewer)
    denied = dashboard._require_sess(
        request("POST", {"test_session": viewer_token, "test_csrf": viewer_csrf}, csrf_header=viewer_csrf)
    )
    assert denied.status_code == 403
