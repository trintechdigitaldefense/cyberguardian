"""CyberGuardian Dashboard — operator UI (wired to API gateway)."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parents[1]
CREDS = ROOT / "data" / "credentials.json"
API_URL = os.getenv("API_URL", "http://127.0.0.1:8080")
API_KEY = os.getenv("CYBERGUARDIAN_API_KEY", "")

app = FastAPI(title="CyberGuardian Dashboard", version="1.4.0-tier3")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
sessions: dict = {}


def load_creds():
    if CREDS.exists():
        try:
            return json.loads(CREDS.read_text())
        except Exception:
            pass
    return {"admin_user": "cyberguardian", "admin_password": os.getenv("CG_ADMIN_PASSWORD", "")}


def check_auth(request: Request):
    token = request.cookies.get("cg_session")
    if token and token in sessions:
        return sessions[token]
    return None


def headers(tenant: str = "default"):
    h = {"X-API-Key": API_KEY}
    if tenant:
        h["X-Tenant-ID"] = tenant
    return h


async def api_get(path: str):
    async with httpx.AsyncClient(timeout=8.0) as client:
        r = await client.get(f"{API_URL}{path}", headers=headers())
        return r


async def api_post(path: str, body: Optional[dict] = None):
    async with httpx.AsyncClient(timeout=12.0) as client:
        r = await client.post(f"{API_URL}{path}", json=body or {}, headers=headers())
        return r


@app.get("/health")
async def health():
    return {"status": "ok", "service": "dashboard", "version": "1.4.0-tier3"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(error: Optional[str] = None):
    err = f'<p style="color:#f87171">{error}</p>' if error else ""
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberGuardian Login</title>
<style>body{{font-family:system-ui;background:#0b0f19;color:#e2e8f0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
.box{{background:#141b2d;border:1px solid #1e293b;border-radius:1rem;padding:2rem;width:90%;max-width:360px}}
h1 span{{color:#22d3ee}} input{{width:100%;padding:.75rem;margin-bottom:1rem;border-radius:.5rem;border:1px solid #1e293b;background:#0b0f19;color:#e2e8f0;box-sizing:border-box}}
button{{width:100%;padding:.75rem;border:none;border-radius:.5rem;background:#0e7490;color:#fff;font-weight:600;cursor:pointer}}</style></head>
<body><div class="box"><h1>Cyber<span>Guardian</span></h1>
<form method="post" action="/login">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign in</button></form>{err}</div></body></html>"""


@app.post("/login")
async def do_login(username: str = Form(...), password: str = Form(...)):
    c = load_creds()
    user = c.get("admin_user") or c.get("username") or "cyberguardian"
    pw = c.get("admin_password") or c.get("password") or ""
    if not pw or username != user or password != pw:
        return RedirectResponse("/login?error=Invalid%20credentials", status_code=303)
    token = secrets.token_urlsafe(24)
    sessions[token] = {"user": username, "tenant": "default"}
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("cg_session", token, httponly=True, samesite="lax")
    return resp


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("cg_session")
    if token and token in sessions:
        del sessions[token]
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("cg_session")
    return resp


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    sess = check_auth(request)
    if not sess:
        return RedirectResponse("/login", status_code=303)
    risk, fleet, gate, mode, issues = {}, {}, {}, {}, {}
    async with httpx.AsyncClient(timeout=8.0) as client:
        h = headers()
        for key, path in [
            ("risk", "/v1/risk/summary"),
            ("fleet", "/v1/fleet"),
            ("gate", "/v1/gate"),
            ("mode", "/v1/client-mode"),
            ("issues", "/v1/issues/client-view"),
        ]:
            try:
                r = await client.get(f"{API_URL}{path}", headers=h)
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
        {"user": sess["user"], "risk": risk, "fleet": fleet, "gate": gate, "mode": mode, "issues": issues},
    )


def _require_sess(request: Request):
    if not check_auth(request):
        return JSONResponse({"error": "auth"}, status_code=401)
    return None


@app.get("/ops/client-mode")
async def ops_get_mode(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/client-mode")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/ops/client-mode")
async def ops_set_mode(request: Request):
    if err := _require_sess(request):
        return err
    body = await request.json()
    r = await api_post("/v1/client-mode", body)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/issues")
async def ops_issues(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/issues/client-view")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/gate")
async def ops_gate(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/gate")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/ops/gate/approve/{action_id}")
async def ops_gate_approve(action_id: str, request: Request):
    if err := _require_sess(request):
        return err
    r = await api_post(f"/v1/gate/approve/{action_id}")
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}
    return JSONResponse(body, status_code=r.status_code)


@app.post("/ops/gate/reject/{action_id}")
async def ops_gate_reject(action_id: str, request: Request):
    if err := _require_sess(request):
        return err
    r = await api_post(f"/v1/gate/reject/{action_id}")
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}
    return JSONResponse(body, status_code=r.status_code)


@app.get("/ops/fleet")
async def ops_fleet(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/fleet")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/risk")
async def ops_risk(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/risk/summary")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/inventory")
async def ops_inventory(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/inventory/report")
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
    r = await api_get("/v1/audit?limit=40")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/scorecard")
async def ops_scorecard(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/pilot/scorecard")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/weekly")
async def ops_weekly(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/reports/weekly")
    return PlainTextResponse(r.text, status_code=r.status_code)


@app.post("/ops/rollback/{asset_id}")
async def ops_rollback(asset_id: str, request: Request):
    if err := _require_sess(request):
        return err
    try:
        body = await request.json()
    except Exception:
        body = {}
    r = await api_post(f"/v1/rollback/{asset_id}", body)
    try:
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception:
        return JSONResponse({"raw": r.text}, status_code=r.status_code)


@app.post("/ops/feedback/benign")
async def ops_benign(request: Request):
    if err := _require_sess(request):
        return err
    body = await request.json()
    r = await api_post("/v1/feedback/benign", body)
    try:
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception:
        return JSONResponse({"raw": r.text}, status_code=r.status_code)


@app.get("/ops/feedback")
async def ops_feedback(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/feedback")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/hardening")
async def ops_hardening(request: Request):
    if err := _require_sess(request):
        return err
    r = await api_get("/v1/hardening")
    return JSONResponse(r.json(), status_code=r.status_code)
