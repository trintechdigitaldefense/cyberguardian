"""Fail-closed command-envelope verification and durable replay protection."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


DISRUPTIVE_ACTIONS = {"isolate_host", "kill_process", "block_ip"}


def _secret() -> str:
    for name in ("CG_COMMAND_SIGNING_SECRET", "CG_AGENT_IDENTITY_SECRET"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


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


def sign_command(command: Dict[str, Any], secret: Optional[str] = None) -> str:
    key = secret if secret is not None else _secret()
    if not key:
        return ""
    return hmac.new(key.encode("utf-8"), canonical_payload(command), hashlib.sha256).hexdigest()


def verify_command(
    command: Dict[str, Any],
    secret: Optional[str] = None,
    *,
    expected_asset_id: Optional[str] = None,
    expected_tenant_id: Optional[str] = None,
) -> Tuple[bool, str]:
    key = secret if secret is not None else _secret()
    production = (os.environ.get("CG_PRODUCTION") or "").lower() in ("1", "true", "yes")
    require = production or (os.environ.get("CG_REQUIRE_COMMAND_SIG") or "").lower() in ("1", "true", "yes")

    command_id = str(command.get("command_id") or command.get("id") or "")
    asset_id = str(command.get("asset_id") or "")
    tenant_id = str(command.get("tenant_id") or "")
    action = str(command.get("action") or "")
    params = command.get("parameters") if isinstance(command.get("parameters"), dict) else {}
    expires_at = command.get("expires_at") or command.get("_expires_at") or params.get("_expires_at") or 0
    nonce = str(command.get("nonce") or "")
    approval_ref = str(
        command.get("approval_ref")
        or command.get("pending_action_id")
        or params.get("_approval_id")
        or ""
    )

    if not all((command_id, asset_id, tenant_id, action)):
        return False, "missing_required_fields"
    if expected_asset_id is not None and asset_id != expected_asset_id:
        return False, "wrong_asset"
    if expected_tenant_id is not None and tenant_id != expected_tenant_id:
        return False, "wrong_tenant"
    try:
        expiry = float(expires_at)
    except (TypeError, ValueError):
        return False, "invalid_expiry"
    now = time.time()
    if expiry <= now or expiry > now + 3600:
        return False, "command_expired_or_expiry_too_far"
    if len(nonce) < 16:
        return False, "missing_or_weak_nonce"
    if action in DISRUPTIVE_ACTIONS and not approval_ref:
        return False, "approval_reference_required"

    signature = str(command.get("signature") or command.get("sig") or "")
    if not signature:
        if require:
            return False, "missing_signature"
        return True, "lab_unsigned_ok"
    if not key:
        return False, "signing_secret_required"
    expected = sign_command(command, key)
    if not hmac.compare_digest(expected, signature):
        return False, "bad_signature"
    return True, "ok"


def claim_command(command: Dict[str, Any], state_path: Optional[Path] = None) -> bool:
    """Atomically claim a command ID and nonce once; returns False on replay."""
    command_id = str(command.get("command_id") or command.get("id") or "")
    nonce = str(command.get("nonce") or "")
    params = command.get("parameters") if isinstance(command.get("parameters"), dict) else {}
    expires_at = float(command.get("expires_at") or command.get("_expires_at") or params.get("_expires_at") or 0)
    if not command_id or len(nonce) < 16 or expires_at <= time.time():
        return False

    if state_path is None:
        state_dir = Path(os.environ.get("CG_STATE_DIR") or (Path.home() / ".cyberguardian"))
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        db_path = state_dir / "command_replay.sqlite3"
    else:
        db_path = Path(state_path)
        db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    connection = sqlite3.connect(str(db_path), timeout=10)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS consumed_commands (command_id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, expires_at REAL NOT NULL, consumed_at REAL NOT NULL)"
        )
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM consumed_commands WHERE expires_at < ?", (time.time() - 86400,))
        connection.execute(
            "INSERT INTO consumed_commands(command_id, nonce, expires_at, consumed_at) VALUES(?,?,?,?)",
            (command_id, nonce, expires_at, time.time()),
        )
        connection.commit()
        try:
            db_path.chmod(0o600)
        except OSError:
            pass
        return True
    except sqlite3.IntegrityError:
        connection.rollback()
        return False
    finally:
        connection.close()
