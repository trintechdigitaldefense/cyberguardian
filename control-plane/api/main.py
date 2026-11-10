"""Bootstrap and security middleware for the assembled CyberGuardian API gateway."""
from __future__ import annotations

import importlib.util
import hmac
import json
import logging
import os
import re
import subprocess
import time
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

from starlette.requests import Request
from starlette.responses import JSONResponse

from agent_credentials import active_agent_api_keys, find_agent_by_api_key, get_agent_credential
from command_signing import sign_envelope
from audit_ledger import append_event as _append_audit_ledger_event
from fleet_lifecycle import project_fleet_lifecycle

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


@app.on_event("startup")
async def _validate_workload_credentials():
    if not _mod._agent_id.production_mode():
        return
    names = (
        "CYBERGUARDIAN_API_KEY",
        "CG_DASHBOARD_API_KEY",
        "CG_NAD_API_KEY",
        "CG_OPERATOR_ASSERTION_SECRET",
        "DECISION_SERVICE_API_KEY",
    )
    values = [os.environ.get(name, "").strip() for name in names]
    configured_admin = _mod.admin_key()
    if not configured_admin or not hmac.compare_digest(configured_admin, values[0]):
        raise RuntimeError("configured administrator API key must match the controller credential store")
    values[0] = configured_admin
    if any(len(value.encode("utf-8")) < 32 for value in values):
        raise RuntimeError("all production service credentials and signing secrets must be at least 32 bytes")
    if len(set(values)) != len(values):
        raise RuntimeError("administrator, workload, decision-service and operator secrets must all be unique")

# Dashboard operator assertions are verified at the gateway boundary. Agent
# credentials are handled by the existing asset-scoped middleware below.
import operator_context as _operator_context
from service_auth import dashboard_scope_allows, nad_scope_allows
_logger = logging.getLogger("cyberguardian.operator_audit")
_original_write_audit = _mod.write_audit
_original_is_admin = _mod.is_admin
_AUDIT_LEDGER_PATH = Path(
    os.environ.get("CG_AUDIT_LEDGER_PATH")
    or (Path(os.environ.get("CG_DATA_DIR", str(_ROOT.parents[1] / "data"))) / "audit_ledger.jsonl")
)


def _is_admin_with_operator(key: str):
    claims = _operator_context.CURRENT_OPERATOR.get()
    dashboard_key = os.environ.get("CG_DASHBOARD_API_KEY", "")
    if (
        claims
        and dashboard_key
        and key
        and hmac.compare_digest(key, dashboard_key)
        and claims.get("role") in {"admin", "operator"}
    ):
        return True
    return _original_is_admin(key)


_mod.is_admin = _is_admin_with_operator


def _write_audit_with_operator(*args, **kwargs):
    claims = _operator_context.CURRENT_OPERATOR.get()
    if claims:
        kwargs["actor"] = claims["sub"]
        detail = str(kwargs.get("detail") or "")
        context = json.dumps({
            "actor_role": claims["role"],
            "tenant_id": claims["tenant_id"],
            "request_id": claims["request_id"],
        }, sort_keys=True, separators=(",", ":"))
        kwargs["detail"] = (detail + " | " + context).strip(" |")
    result = _original_write_audit(*args, **kwargs)
    # The independent ledger is appended after the transactional gateway
    # audit write. If the chain cannot be extended, propagate the failure so
    # callers that require an audit record can fail closed.
    _append_audit_ledger_event(
        _AUDIT_LEDGER_PATH,
        {"args": list(args), "fields": kwargs},
    )
    return result


_mod.write_audit = _write_audit_with_operator


def _asset_matches_tenant(asset_id: str, tenant_id: str) -> bool:
    if not asset_id:
        return False
    try:
        with _mod.db() as conn:
            row = conn.execute(
                "SELECT tenant_id FROM assets WHERE asset_id = ?",
                (asset_id,),
            ).fetchone()
    except Exception:
        _logger.exception("asset tenant lookup failed")
        return False
    return bool(row) and str(row["tenant_id"] or "default") == tenant_id


def _pending_action_matches_tenant(action_id: str, tenant_id: str) -> bool:
    if not action_id:
        return False
    try:
        with _mod.db() as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(pending_actions)")}
            if "id" not in columns:
                return False
            if "asset_id" in columns:
                row = conn.execute(
                    "SELECT asset_id" + (", tenant_id" if "tenant_id" in columns else "")
                    + " FROM pending_actions WHERE id = ?",
                    (action_id,),
                ).fetchone()
                if not row:
                    return False
                if "tenant_id" in columns and str(row["tenant_id"] or "default") != tenant_id:
                    return False
                return _asset_matches_tenant(str(row["asset_id"] or ""), tenant_id)
            if "tenant_id" in columns:
                row = conn.execute(
                    "SELECT tenant_id FROM pending_actions WHERE id = ?", (action_id,)
                ).fetchone()
                return bool(row) and str(row["tenant_id"] or "default") == tenant_id
    except Exception:
        _logger.exception("pending action tenant lookup failed")
    return False


def _deny_verified_operator(request: Request, claims: dict, reason: str, status_code: int = 403):
    context_token = _operator_context.CURRENT_OPERATOR.set(claims)
    try:
        _mod.write_audit(
            event="operator_request_denied",
            action=request.method,
            target=request.url.path,
            actor=claims["sub"],
            detail=reason,
            result_ok=0,
        )
    except Exception:
        _logger.exception("operator denial audit write failed")
    finally:
        _operator_context.CURRENT_OPERATOR.reset(context_token)
    return JSONResponse({"detail": reason}, status_code=status_code)


def _item_matches_tenant(item: dict, tenant_id: str) -> bool:
    item_tenant = item.get("tenant_id")
    if item_tenant is not None:
        return str(item_tenant or "default") == tenant_id
    detail = str(item.get("detail") or "")
    marker = detail.rfind("{")
    if marker >= 0:
        try:
            detail_context = json.loads(detail[marker:])
            if detail_context.get("tenant_id") is not None:
                return str(detail_context["tenant_id"]) == tenant_id
        except (ValueError, TypeError):
            pass
    asset_id = str(item.get("asset_id") or "")
    if asset_id:
        return _asset_matches_tenant(asset_id, tenant_id)
    pending_id = str(item.get("pending_action_id") or item.get("id") or "")
    if pending_id:
        return _pending_action_matches_tenant(pending_id, tenant_id)
    return False


async def _filter_dashboard_tenant_response(response, tenant_id: str, path: str):
    list_key = {
        "/v1/fleet": "items",
        "/v1/gate": "pending",
        "/v1/audit": "items",
        "/v1/feedback": "items",
        "/v1/issues/client-view": "items",
    }.get(path)
    if not list_key or response.status_code >= 400:
        return response
    content_type = str(response.headers.get("content-type") or "")
    if "application/json" not in content_type:
        return response
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeError, ValueError):
        return JSONResponse({"detail": "tenant response could not be validated"}, status_code=502)
    if not isinstance(payload, dict) or not isinstance(payload.get(list_key), list):
        return JSONResponse({"detail": "tenant response shape could not be validated"}, status_code=502)
    filtered = [item for item in payload[list_key] if isinstance(item, dict) and _item_matches_tenant(item, tenant_id)]
    if path == "/v1/fleet":
        try:
            stale_after = int(os.environ.get("CG_AGENT_STALE_AFTER_SECONDS", "180"))
        except ValueError:
            stale_after = 180
        filtered = project_fleet_lifecycle(
            filtered,
            now=time.time(),
            stale_after_seconds=stale_after,
        )
    payload[list_key] = filtered
    if path == "/v1/gate":
        payload["pending_count"] = len(filtered)
    elif path == "/v1/fleet":
        payload["total"] = len(filtered)
        payload["online"] = sum(1 for item in filtered if item.get("status") == "online")
        payload["offline"] = sum(1 for item in filtered if item.get("status") != "online")
    elif "count" in payload:
        payload["count"] = len(filtered)
    headers = {
        key: value for key, value in response.headers.items()
        if key.lower() not in {"content-length", "content-type", "transfer-encoding"}
    }
    return JSONResponse(
        payload,
        status_code=response.status_code,
        headers=headers,
        background=getattr(response, "background", None),
    )


@app.middleware("http")
async def _verify_dashboard_operator(request: Request, call_next):
    api_key = str(request.headers.get("X-API-Key") or "")
    dashboard_key = str(os.environ.get("CG_DASHBOARD_API_KEY") or "")
    nad_key = str(os.environ.get("CG_NAD_API_KEY") or "")
    is_agent = bool(api_key and find_agent_by_api_key(api_key))
    if not is_agent and nad_key and hmac.compare_digest(api_key, nad_key):
        if not nad_scope_allows(request.method, request.url.path):
            return JSONResponse({"detail": "NAD service is not authorized for this endpoint"}, status_code=403)
        return await call_next(request)
    if not is_agent and dashboard_key and hmac.compare_digest(api_key, dashboard_key) and request.url.path != "/health":
        if not dashboard_scope_allows(request.method, request.url.path):
            return JSONResponse({"detail": "dashboard service is not authorized for this endpoint"}, status_code=403)
        if not _mod._agent_id.production_mode():
            return await call_next(request)
        secret = os.environ.get("CG_OPERATOR_ASSERTION_SECRET", "")
        if len(secret.encode("utf-8")) < 32:
            return JSONResponse({"detail": "operator assertion verification is not configured"}, status_code=503)
        assertion = request.headers.get("X-CG-Operator-Assertion", "")
        tenant_id = str(request.headers.get("X-Tenant-ID") or "")
        if not assertion or not tenant_id:
            return JSONResponse({"detail": "verified operator context required"}, status_code=401)
        try:
            claims = _operator_context.verify_assertion(
                assertion,
                secret=secret,
                method=request.method,
                path=request.url.path,
                tenant_id=tenant_id,
                replay_db=Path(os.environ.get("CG_DATA_DIR", "/app/data")) / "operator_assertion_nonces.sqlite3",
            )
        except _operator_context.AssertionError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=403)
        requested_tenants = request.query_params.getlist("tenant_id")
        if any(value != claims["tenant_id"] for value in requested_tenants):
            return _deny_verified_operator(request, claims, "operator tenant does not match requested tenant")
        raw_body = await request.body()
        if raw_body:
            try:
                body_claims = json.loads(raw_body.decode("utf-8"))
            except (UnicodeError, ValueError):
                return _deny_verified_operator(request, claims, "invalid JSON request body", 400)
            if isinstance(body_claims, dict):
                body_tenant = body_claims.get("tenant_id")
                if body_tenant and str(body_tenant) != claims["tenant_id"]:
                    return _deny_verified_operator(request, claims, "operator tenant does not match request body tenant")
                if request.url.path == "/v1/feedback/benign":
                    asset_id = str(body_claims.get("asset_id") or "")
                    pending_id = str(body_claims.get("pending_action_id") or "")
                    if asset_id and not _asset_matches_tenant(asset_id, claims["tenant_id"]):
                        return _deny_verified_operator(request, claims, "asset is outside the operator tenant")
                    if pending_id and not _pending_action_matches_tenant(pending_id, claims["tenant_id"]):
                        return _deny_verified_operator(request, claims, "pending action is outside the operator tenant")

        rollback_match = re.fullmatch(r"/v1/rollback/([A-Za-z0-9_.:-]{1,128})", request.url.path)
        if rollback_match and not _asset_matches_tenant(rollback_match.group(1), claims["tenant_id"]):
            return _deny_verified_operator(request, claims, "asset is outside the operator tenant")
        pending_match = re.fullmatch(
            r"/v1/gate/(?:approve|reject)/([A-Za-z0-9_.:-]{1,128})",
            request.url.path,
        )
        if pending_match and not _pending_action_matches_tenant(pending_match.group(1), claims["tenant_id"]):
            return _deny_verified_operator(request, claims, "pending action is outside the operator tenant")

        async def replay_operator_body():
            nonlocal raw_body
            payload = raw_body
            raw_body = b""
            return {"type": "http.request", "body": payload, "more_body": False}

        # Pass the authenticated tenant into gateway handlers that expose a
        # tenant_id query filter. Routes without that parameter ignore it.
        query_pairs = parse_qsl(
            request.scope.get("query_string", b"").decode("latin-1"),
            keep_blank_values=True,
        )
        if not any(key == "tenant_id" for key, _ in query_pairs):
            query_pairs.append(("tenant_id", claims["tenant_id"]))
        request.scope["query_string"] = urlencode(query_pairs).encode("ascii")
        request = Request(request.scope, replay_operator_body)
        request.state.operator_context = claims
        context_token = _operator_context.CURRENT_OPERATOR.set(claims)
        try:
            # Persist an authorization record before a state-changing handler
            # can run. If the audit store is unavailable, fail closed.
            try:
                _mod.write_audit(
                    event="operator_request_started",
                    action=request.method,
                    target=request.url.path,
                    actor=claims["sub"],
                    detail="operator request authorized",
                    result_ok=1,
                )
            except Exception:
                _logger.exception("operator audit start write failed")
                return JSONResponse({"detail": "operator audit store unavailable"}, status_code=503)
            response = await call_next(request)
            response = await _filter_dashboard_tenant_response(
                response, claims["tenant_id"], request.url.path,
            )
            try:
                _mod.write_audit(
                    event="operator_request_completed",
                    action=request.method,
                    target=request.url.path,
                    actor=claims["sub"],
                    detail=f"HTTP {response.status_code}",
                    result_ok=1 if response.status_code < 400 else 0,
                )
            except Exception:
                # The start record remains durable and explicitly shows that
                # the request entered the handler; operators must investigate.
                _logger.exception("operator audit completion write failed")
            return response
        finally:
            _operator_context.CURRENT_OPERATOR.reset(context_token)
    return await call_next(request)

# Extend the gateway's accepted API-key set with active per-agent keys. Admin
# authorization remains separate because _mod.is_admin() only accepts admin_key().
_original_valid_keys = _mod.valid_keys


def _valid_keys() -> set[str]:
    service_keys = {
        value for value in (
            os.environ.get("CG_DASHBOARD_API_KEY", "").strip(),
            os.environ.get("CG_NAD_API_KEY", "").strip(),
        ) if value
    }
    return set(_original_valid_keys()) | service_keys | active_agent_api_keys()


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
    nad_key = str(os.environ.get("CG_NAD_API_KEY") or "")
    if nad_key and hmac.compare_digest(api_key, nad_key) and nad_scope_allows(request.method, path):
        return await call_next(request)

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
