"""CyberGuardian Dashboard — operator UI."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parents[1]
CREDS = ROOT / "data" / "credentials.json"
API_URL = os.getenv("API_URL", "http://127.0.0.1:8080")
API_KEY = os.getenv("CYBERGUARDIAN_API_KEY", "")

app = FastAPI(title="CyberGuardian Dashboard", version="1.0.0")
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


@app.get("/health")
async def health():
    return {"status": "ok", "service": "dashboard"}


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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    sess = check_auth(request)
    if not sess:
        return RedirectResponse("/login", status_code=303)
    risk, fleet, gate, mode = {}, {}, {}, {}
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            risk = (await client.get(f"{API_URL}/v1/risk/summary", headers=headers())).json()
        except Exception:
            risk = {"error": "api unreachable"}
        try:
            fleet = (await client.get(f"{API_URL}/v1/fleet", headers=headers())).json()
        except Exception:
            fleet = {}
        try:
            gate = (await client.get(f"{API_URL}/v1/gate", headers=headers())).json()
        except Exception:
            gate = {}
        try:
            mode = (await client.get(f"{API_URL}/v1/client-mode", headers=headers())).json()
        except Exception:
            mode = {"client_mode": True}
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": sess["user"],
            "risk": risk,
            "fleet": fleet,
            "gate": gate,
            "mode": mode,
        },
    )


@app.get("/ops/client-mode")
async def ops_get_mode(request: Request):
    if not check_auth(request):
        return JSONResponse({"error": "auth"}, status_code=401)
    async with httpx.AsyncClient(timeout=8.0) as client:
        r = await client.get(f"{API_URL}/v1/client-mode", headers=headers())
        return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/ops/client-mode")
async def ops_set_mode(request: Request):
    if not check_auth(request):
        return JSONResponse({"error": "auth"}, status_code=401)
    body = await request.json()
    async with httpx.AsyncClient(timeout=8.0) as client:
        r = await client.post(f"{API_URL}/v1/client-mode", json=body, headers=headers())
        return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/ops/issues")
async def ops_issues(request: Request):
    if not check_auth(request):
        return JSONResponse({"error": "auth"}, status_code=401)
    async with httpx.AsyncClient(timeout=8.0) as client:
        r = await client.get(f"{API_URL}/v1/issues/client-view", headers=headers())
        return JSONResponse(r.json(), status_code=r.status_code)
