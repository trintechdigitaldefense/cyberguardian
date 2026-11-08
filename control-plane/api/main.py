"""Bootstrap and security middleware for the assembled CyberGuardian API gateway."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse

from agent_credentials import active_agent_api_keys, find_agent_by_api_key, get_agent_credential
from command_signing import sign_envelope

_ROOT = Path(__file__).resolve().parent
_FULL = _ROOT / "main_full.py"


def _ensure() -> Path:
    assembler = _ROOT / "assemble_main.py"
    result = subprocess.run(
        [sys.executable, str(assembler)],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout or "gateway assembly failed")
    if not _FULL.is_file() or _FULL.stat().st_size < 20_000:
        raise RuntimeError("assembled gateway missing or unexpected size")
    return _FULL


_target = _ensure()
_spec = importlib.util.spec_from_file_location("cg_api_main", _target)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load assembled gateway")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["cg_api_main"] = _mod
_spec.loader.exec_module(_mod)
app = _mod.app

# Extend the gateway's accepted API-key set with active per-agent keys. Admin
# authorization remains separate because _mod.is_admin() only accepts admin_key().
_original_valid_keys = _mod.valid_keys


def _valid_keys() -> set[str]:
    return set(_original_valid_keys()) | active_agent_api_keys()


_mod.valid_keys = _valid_keys


@app.middleware("http")
async def _agent_scope_and_command_signing(request: Request, call_next):
    path = request.url.path
    agent_paths = {
        "/v1/assets/register",
        "/v1/agent/commands",
        "/v1/agent/command-result",
        "/v1/detections",
    }
    api_key = str(request.headers.get("X-API-Key") or "")
    agent_match = find_agent_by_api_key(api_key) if api_key else None

    # Agent credentials are deliberately limited to the agent's own endpoints.
    # They must never become general-purpose API keys for fleet/admin reads.
    if agent_match and path not in agent_paths:
        return JSONResponse({"detail": "agent key is not authorized for this endpoint"}, status_code=403)
    if path not in agent_paths:
        return await call_next(request)

    body = await request.body()

    async def replay_body():
        nonlocal body
        payload = body
        body = b""
        return {"type": "http.request", "body": payload, "more_body": False}

    request = Request(request.scope, replay_body)
    body_data = {}
    if request.method in ("POST", "PUT") and body:
        try:
            body_data = json.loads(body.decode("utf-8"))
        except (UnicodeError, ValueError):
            return JSONResponse({"detail": "invalid agent request body"}, status_code=400)

    asset_id = str(
        request.query_params.get("asset_id")
        or (body_data.get("asset_id") if isinstance(body_data, dict) else "")
        or ""
    )
    tenant_id = str(
        request.headers.get("X-Tenant-ID")
        or (body_data.get("tenant_id") if isinstance(body_data, dict) else "")
        or "default"
    )
    strict = bool(_mod._agent_id.production_mode())
    record = get_agent_credential(asset_id) if asset_id else None

    if agent_match:
        bound_asset, bound_record = agent_match
        if asset_id != bound_asset:
            return JSONResponse({"detail": "agent key is not bound to the requested asset"}, status_code=403)
        if tenant_id != str(bound_record.get("tenant_id") or "default"):
            return JSONResponse({"detail": "agent tenant does not match enrolled tenant"}, status_code=403)
        record = bound_record
    elif record:
        if not api_key or api_key != str(record.get("api_key") or ""):
            return JSONResponse({"detail": "agent key does not match asset"}, status_code=403)
        if tenant_id != str(record.get("tenant_id") or "default"):
            return JSONResponse({"detail": "agent tenant does not match enrolled tenant"}, status_code=403)
    elif strict:
        return JSONResponse({"detail": "active per-agent enrollment required"}, status_code=403)
    else:
        ok, reason = _mod._agent_id.assert_not_admin_key_on_agent(api_key)
        if not ok:
            return JSONResponse({"detail": f"agent authentication rejected: {reason}"}, status_code=403)

    response = await call_next(request)

    if path != "/v1/agent/commands" or response.status_code != 200:
        return response

    secret = str((record or {}).get("command_secret") or os.environ.get("CG_COMMAND_SIGNING_SECRET") or "")
    if not secret:
        if strict:
            return JSONResponse({"detail": "command signing is not configured"}, status_code=503)
        return response

    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)
    try:
        result = json.loads(b"".join(chunks).decode("utf-8"))
        commands = result.get("commands") or []
        signed = []
        for command in commands:
            if str(command.get("asset_id") or "") != asset_id:
                return JSONResponse({"detail": "queued command asset mismatch"}, status_code=403)
            signed.append(sign_envelope(command, tenant_id=tenant_id, secret=secret))
        result["commands"] = signed
    except (UnicodeError, ValueError, TypeError) as exc:
        return JSONResponse({"detail": f"command signing failed: {exc}"}, status_code=500)

    return JSONResponse(result, status_code=response.status_code)
