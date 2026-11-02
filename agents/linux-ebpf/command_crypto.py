"""Verify signed command envelopes from the control plane."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional, Tuple


def _secret() -> str:
    for env in ("CG_COMMAND_SIGNING_SECRET", "CG_AGENT_IDENTITY_SECRET"):
        v = (os.environ.get(env) or "").strip()
        if v:
            return v
    key = (os.environ.get("CYBERGUARDIAN_API_KEY") or os.environ.get("CG_AGENT_KEY") or "").strip()
    if key:
        return hashlib.sha256(f"cg-cmd-sign:{key}".encode()).hexdigest()
    return ""


def canonical_payload(cmd: Dict[str, Any]) -> bytes:
    body = {
        "command_id": str(cmd.get("command_id") or cmd.get("id") or ""),
        "asset_id": str(cmd.get("asset_id") or ""),
        "tenant_id": str(cmd.get("tenant_id") or "default"),
        "action": str(cmd.get("action") or ""),
        "target": str(cmd.get("target") or ""),
        "parameters": cmd.get("parameters") if isinstance(cmd.get("parameters"), dict) else {},
        "expires_at": float(cmd.get("expires_at") or cmd.get("_expires_at") or 0),
        "approval_ref": str(cmd.get("approval_ref") or cmd.get("pending_action_id") or ""),
        "nonce": str(cmd.get("nonce") or ""),
    }
    params = {k: v for k, v in (body["parameters"] or {}).items() if not str(k).startswith("_")}
    body["parameters"] = params
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_command(cmd: Dict[str, Any], secret: Optional[str] = None) -> str:
    sec = secret if secret is not None else _secret()
    if not sec:
        return ""
    return hmac.new(sec.encode(), canonical_payload(cmd), hashlib.sha256).hexdigest()


def verify_command(cmd: Dict[str, Any], secret: Optional[str] = None) -> Tuple[bool, str]:
    sec = secret if secret is not None else _secret()
    production = (os.environ.get("CG_PRODUCTION") or "").lower() in ("1", "true", "yes")
    require = production or (os.environ.get("CG_REQUIRE_COMMAND_SIG") or "").lower() in ("1", "true", "yes")

    cid = str(cmd.get("command_id") or cmd.get("id") or "")
    asset = str(cmd.get("asset_id") or "")
    action = str(cmd.get("action") or "")
    if not cid or not asset or not action:
        return False, "missing_required_fields"

    exp = float(cmd.get("expires_at") or 0)
    if not exp and isinstance(cmd.get("parameters"), dict):
        exp = float(cmd["parameters"].get("_expires_at") or 0)
    if exp and time.time() > exp:
        return False, "command_expired"

    sig = str(cmd.get("signature") or cmd.get("sig") or "")
    if not sec:
        if require:
            return False, "signing_secret_required"
        return True, "lab_unsigned_ok"

    if not sig:
        return False, "missing_signature"

    expected = sign_command(cmd, sec)
    if not hmac.compare_digest(expected, sig):
        return False, "bad_signature"
    return True, "ok"
