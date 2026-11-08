"""Controller-side HMAC signing for agent command envelopes."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict


DISRUPTIVE_ACTIONS = {"isolate_host", "kill_process", "block_ip"}


def canonical_payload(command: Dict[str, Any]) -> bytes:
    params = command.get("parameters")
    if not isinstance(params, dict):
        params = {}
    expires_at = command.get("expires_at") or command.get("_expires_at") or params.get("_expires_at") or 0
    approval_ref = (
        command.get("approval_ref")
        or command.get("pending_action_id")
        or params.get("_approval_id")
        or ""
    )
    body = {
        "command_id": str(command.get("command_id") or command.get("id") or ""),
        "asset_id": str(command.get("asset_id") or ""),
        "tenant_id": str(command.get("tenant_id") or ""),
        "action": str(command.get("action") or ""),
        "target": str(command.get("target") or ""),
        "parameters": params,
        "expires_at": float(expires_at),
        "approval_ref": str(approval_ref),
        "nonce": str(command.get("nonce") or ""),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_command(command: Dict[str, Any], secret: str) -> str:
    if not secret:
        raise ValueError("command signing secret is required")
    return hmac.new(secret.encode("utf-8"), canonical_payload(command), hashlib.sha256).hexdigest()


def sign_envelope(command: Dict[str, Any], *, tenant_id: str, secret: str) -> Dict[str, Any]:
    envelope = dict(command)
    params = envelope.get("parameters")
    if not isinstance(params, dict):
        params = {}
    envelope["parameters"] = params
    envelope["tenant_id"] = str(tenant_id)
    expires_at = float(params.get("_expires_at") or envelope.get("expires_at") or 0)
    now = time.time()
    if expires_at <= now or expires_at > now + 3600:
        raise ValueError("command expiry is missing, expired, or exceeds the one-hour limit")
    envelope["expires_at"] = expires_at
    approval_ref = str(envelope.get("pending_action_id") or params.get("_approval_id") or "")
    if not approval_ref and "[auto allowlist]" in str(envelope.get("reason") or "").lower():
        decision_id = str(envelope.get("decision_id") or "")
        if decision_id:
            approval_ref = f"allowlist:{decision_id}"
    if str(envelope.get("action") or "") in DISRUPTIVE_ACTIONS and not approval_ref:
        raise ValueError("disruptive command is missing its approval reference")
    envelope["approval_ref"] = approval_ref
    envelope["nonce"] = secrets.token_urlsafe(24)
    envelope["signature"] = sign_command(envelope, secret)
    return envelope
