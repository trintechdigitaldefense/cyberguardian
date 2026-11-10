"""CyberGuardian Dashboard — operator UI (wired to API gateway)."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import auth as dashboard_auth

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = dashboard_auth.DATA_DIR
CREDS = dashboard_auth.CREDS_PATH
API_URL = os.getenv("API_URL", "http://127.0.0.1:8080")
API_KEY = os.getenv("CG_DASHBOARD_API_KEY", "")

app = FastAPI(title="CyberGuardian Dashboard", version="1.4.0-tier3")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

@app.on_event("startup")
async def validate_dashboard_credentials():
    if dashboard_auth.PRODUCTION:
        secret = os.getenv("CG_OPERATOR_ASSERTION_SECRET", "")
        if len(API_KEY.encode("utf-8")) < 32 or len(secret.encode("utf-8")) < 32:
            raise RuntimeError("production dashboard service and assertion secrets must be at least 32 bytes")
        if not COOKIE_SECURE:
            raise RuntimeError("CG_COOKIE_SECURE must be enabled in production")
        try:
            _trusted_proxy_networks()
        except ValueError as exc:
            raise RuntimeError("CG_TRUSTED_PROXY_IPS contains an invalid network") from exc


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
        "form-action 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; "
        "script-src-attr 'none'; style-src-attr 'none'",
    )
    if COOKIE_SECURE:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path == "/" or request.url.path == "/login" or request.url.path.startswith("/ops/"):
        response.headers["Cache-Control"] = "no-store"
    return response
COOKIE_SECURE = os.getenv("CG_COOKIE_SECURE", "1" if dashboard_auth.PRODUCTION else "0").strip().lower() in {"1", "true", "yes", "on"}
SESSION_COOKIE = "__Host-cg_session" if COOKIE_SECURE else "cg_session"
CSRF_COOKIE = "__Host-cg_csrf" if COOKIE_SECURE else "cg_csrf"
LOGIN_CSRF_COOKIE = "cg_login_csrf"


def check_auth(request: Request):
    return dashboard_auth.get_session(request.cookies.get(SESSION_COOKIE, ""))


def tenant_for_request(request: Request) -> str:
    session = check_auth(request)
    return str((session or {}).get("tenant_id") or "default")


def _trusted_proxy_networks():
    raw = os.getenv("CG_TRUSTED_PROXY_IPS", "").strip()
    networks = []
    for item in filter(None, (part.strip() for part in raw.split(","))):
        networks.append(ipaddress.ip_network(item, strict=False))
    return networks


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    try:
        peer_ip = ipaddress.ip_address(peer)
        trusted = _trusted_proxy_networks()
    except ValueError:
        return peer
    if not any(peer_ip in network for network in trusted):
        return peer
    forwarded = request.headers.get("X-Forwarded-For", "")
    if not forwarded:
        return peer
    try:
        chain = [ipaddress.ip_address(value.strip()) for value in forwarded.split(",")]
    except ValueError:
        return peer
    # Walk from the directly connected proxy toward the client. Only skip
    # addresses explicitly configured as trusted proxies; ignore spoofed
    # forwarding headers from untrusted peers.
    for candidate in reversed(chain):
        if any(candidate in network for network in trusted):
            continue
        return str(candidate)
    return peer


def headers(tenant: str = "default"):
    h = {"X-API-Key": API_KEY}
    if tenant:
        h["X-Tenant-ID"] = tenant
    return h


def operator_headers(session, method: str, path: str, tenant: str):
    """Mint request-bound operator identity from the server-side session only."""
    result = headers(tenant)
    secret = os.getenv("CG_OPERATOR_ASSERTION_SECRET", "")
    if not secret:
        if dashboard_auth.PRODUCTION:
            raise RuntimeError("CG_OPERATOR_ASSERTION_SECRET must be configured in production")
        return result
    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError("CG_OPERATOR_ASSERTION_SECRET must contain at least 32 bytes")
    if not session:
        raise RuntimeError("authenticated operator session required for gateway request")
    claims = {
        "v": 1,
        "sub": str(session["username"]),
        "role": str(session["role"]),
        "tenant_id": str(session["tenant_id"]),
        "iat": int(time.time()),
        "nonce": secrets.token_urlsafe(32),
        "method": method.upper(),
        "path": path,
        "request_id": uuid.uuid4().hex,
    }
    raw = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    signature = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    result["X-CG-Operator-Assertion"] = encoded + "." + signature
    result["X-Request-ID"] = claims["request_id"]
    return result


async def api_get(path: str, request: Optional[Request] = None):
    async with httpx.AsyncClient(timeout=8.0) as client:
        r = await client.get(f"{API_URL}{path}", headers=operator_headers(check_auth(request), "GET", path.split("?", 1)[0], tenant_for_request(request)) if request else headers("default"))
        return r


async def api_post(path: str, body: Optional[dict] = None, request: Optional[Request] = None):
    async with httpx.AsyncClient(timeout=12.0) as client:
        r = await client.post(
            f"{API_URL}{path}",
            json=body or {},
            headers=operator_headers(check_auth(request), "POST", path.split("?", 1)[0], tenant_for_request(request)) if request else headers("default"),
        )
        return r


@app.get("/health")
async def health():
    return {"status": "ok", "service": "dashboard", "version": "1.4.0-tier3"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    login_csrf = secrets.token_urlsafe(32)
    response = templates.TemplateResponse(
        request, "login.html", {"login_csrf": login_csrf, "error": error or ""},
    )
    response.set_cookie(
        LOGIN_CSRF_COOKIE, login_csrf, httponly=True, secure=COOKIE_SECURE,
        samesite="lax", max_age=600, path="/",
    )
    return response

@app.post("/login")
async def do_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    login_csrf: str = Form(...),
):
    cookie_token = request.cookies.get(LOGIN_CSRF_COOKIE, "")
    if not cookie_token or not hmac.compare_digest(cookie_token, login_csrf):
        return HTMLResponse("Invalid login request. Reload the sign-in page.", status_code=403)
    client_ip = _client_ip(request)
    if dashboard_auth.is_rate_limited(client_ip, username):
        return HTMLResponse("Too many failed sign-in attempts. Try again later.", status_code=429)
    user = dashboard_auth.authenticate_user(username, password)
    dashboard_auth.record_login_attempt(client_ip, username, bool(user))
    if not user:
        return RedirectResponse("/login?error=Invalid%20credentials", status_code=303)
    token, csrf_token, expires = dashboard_auth.create_session(user)
    response = RedirectResponse("/", status_code=303)
    max_age = max(1, int(expires - time.time()))
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, secure=COOKIE_SECURE,
        samesite="lax", max_age=max_age, path="/",
    )
    response.set_cookie(
        CSRF_COOKIE, csrf_token, httponly=True, secure=COOKIE_SECURE,
        samesite="lax", max_age=max_age, path="/",
    )
    response.delete_cookie(LOGIN_CSRF_COOKIE, path="/")
    return response


@app.get("/logout")
async def logout_get():
    # State-changing logout is POST-only to prevent cross-site logout requests.
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    if err := _require_sess(request):
        return err
    dashboard_auth.revoke_session(request.cookies.get(SESSION_COOKIE, ""))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="lax")
    return response

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    sess = check_auth(request)
    if not sess:
        return RedirectResponse("/login", status_code=303)
    risk, fleet, gate, mode, issues = {}, {}, {}, {}, {}
    async with httpx.AsyncClient(timeout=8.0) as client:
        h_by_path = lambda method, path: operator_headers(sess, method, path, str(sess.get("tenant_id") or "default"))
        for key, path in [
            ("risk", "/v1/risk/summary"),
            ("fleet", "/v1/fleet"),
            ("gate", "/v1/gate"),
            ("mode", "/v1/client-mode"),
            ("issues", "/v1/issues/client-view"),
        ]:
            try:
                r = await client.get(f"{API_URL}{path}", headers=h_by_path("GET", path))
                data = r.json() if r.status_code < 400 else {"error": r.status_code}
            except Exception:
                data = {"error": "api unreachable"}
            if key == "risk":
                risk = data
            elif key == "fleet":
                fleet = data
            elif key == "gate":
                gate = data
            elif key == "mode":
                mode = data
            else:
                issues = data
    return templates.TemplateResponse(
        request,
        "index.html",
        {"user": sess["username"], "csrf_token": request.cookies.get(CSRF_COOKIE, ""), "risk": risk, "fleet": fleet, "gate": gate, "mode": mode, "issues": issues},
    )


def _require_sess(request: Request, allowed_roles=None):
    session = check_auth(request)
    if not session:
        return JSONResponse({"error": "auth"}, status_code=401)
    if allowed_roles is None:
        allowed_roles = {"admin", "operator", "analyst", "viewer"} if request.method == "GET" else {"admin", "operator"}
    if session.get("role") not in allowed_roles:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.headers.get("X-CSRF-Token", "")
        if not dashboard_auth.verify_csrf(session, supplied):
            return JSONResponse({"error": "csrf"}, status_code=403)
    return None

@app.get("/ops/client-mode")
async def ops_get_mode(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/client-mode", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/ops/client-mode")
async def ops_set_mode(request: Request):
    if err := _require_sess(request, {"admin"}):
        return err
    body = await request.json()
    r = await api_post("/v1/client-mode", body, request=request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/issues")
async def ops_issues(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/issues/client-view", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/gate")
async def ops_gate(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/gate", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/ops/gate/approve/{action_id}")
async def ops_gate_approve(action_id: str, request: Request):
    if err := _require_sess(request):
        return err
    r = await api_post(f"/v1/gate/approve/{action_id}", request=request)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}
    return JSONResponse(body, status_code=r.status_code)


@app.post("/ops/gate/reject/{action_id}")
async def ops_gate_reject(action_id: str, request: Request):
    if err := _require_sess(request):
        return err
    r = await api_post(f"/v1/gate/reject/{action_id}", request=request)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}
    return JSONResponse(body, status_code=r.status_code)


@app.get("/ops/fleet")
async def ops_fleet(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/fleet", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/risk")
async def ops_risk(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/risk/summary", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/inventory")
async def ops_inventory(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/inventory/report", request)
    return PlainTextResponse(r.text, status_code=r.status_code)


@app.get("/ops/status")
async def ops_status(request: Request):
    if err := _require_sess(request):
        return err
    out = {"api": False, "decision": False, "dashboard": True}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{API_URL}/health")
            out["api"] = r.status_code == 200
    except Exception:
        pass
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(os.getenv("DECISION_SERVICE_URL", "http://127.0.0.1:8001") + "/health")
            out["decision"] = r.status_code == 200
    except Exception:
        pass
    return JSONResponse(out)


@app.get("/ops/audit")
async def ops_audit(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/audit?limit=40", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/scorecard")
async def ops_scorecard(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/pilot/scorecard", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/weekly")
async def ops_weekly(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/reports/weekly", request)
    return PlainTextResponse(r.text, status_code=r.status_code)


@app.post("/ops/rollback/{asset_id}")
async def ops_rollback(asset_id: str, request: Request):
    if err := _require_sess(request):
        return err
    try:
        body = await request.json()
    except Exception:
        body = {}
    r = await api_post(f"/v1/rollback/{asset_id}", body, request=request)
    try:
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception:
        return JSONResponse({"raw": r.text}, status_code=r.status_code)


@app.post("/ops/feedback/benign")
async def ops_benign(request: Request):
    if err := _require_sess(request):
        return err
    body = await request.json()
    r = await api_post("/v1/feedback/benign", body, request=request)
    try:
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception:
        return JSONResponse({"raw": r.text}, status_code=r.status_code)


@app.get("/ops/feedback")
async def ops_feedback(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/feedback", request)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/hardening")
async def ops_hardening(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/hardening", request)
    return JSONResponse(r.json(), status_code=r.status_code)
