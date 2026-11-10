"""HMAC-signed, request-bound dashboard operator assertions.

Assertions are minted only by the dashboard backend from its persistent session.
The gateway consumes each nonce in a shared SQLite database before accepting it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

MAX_AGE_SECONDS = 60
MAX_FUTURE_SKEW_SECONDS = 5
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class AssertionError(ValueError):
    """Raised when an operator assertion is invalid or has been replayed."""


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _key(secret: str | bytes) -> bytes:
    value = secret.encode("utf-8") if isinstance(secret, str) else secret
    if len(value) < 32:
        raise AssertionError("operator assertion secret must contain at least 32 bytes")
    return value


def mint_assertion(
    *, secret: str | bytes, subject: str, role: str, tenant_id: str,
    method: str, path: str, request_id: str, now: float | None = None,
) -> str:
    if not all(isinstance(v, str) and v.strip() for v in (subject, role, tenant_id, method, path, request_id)):
        raise AssertionError("operator assertion claims must be non-empty strings")
    payload = {
        "v": 1, "sub": subject, "role": role, "tenant_id": tenant_id,
        "iat": int(time.time() if now is None else now),
        "nonce": secrets.token_urlsafe(32), "method": method.upper(),
        "path": path, "request_id": request_id,
    }
    raw = _canonical(payload)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    signature = hmac.new(_key(secret), raw, hashlib.sha256).hexdigest()
    return encoded + "." + signature


def verify_assertion(
    token: str, *, secret: str | bytes, method: str, path: str, tenant_id: str,
    replay_db: str | Path, now: float | None = None,
) -> dict[str, Any]:
    try:
        encoded, supplied_sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssertionError("malformed operator assertion") from exc
    expected_sig = hmac.new(_key(secret), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, supplied_sig):
        raise AssertionError("invalid operator assertion signature")
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise AssertionError("unsupported operator assertion")
    required = ("sub", "role", "tenant_id", "method", "path", "request_id", "nonce")
    if any(not isinstance(payload.get(k), str) or not payload[k].strip() for k in required):
        raise AssertionError("incomplete operator assertion")
    if not _NONCE_RE.fullmatch(payload["nonce"]):
        raise AssertionError("invalid operator assertion nonce")
    try:
        issued = int(payload["iat"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AssertionError("invalid operator assertion issue time") from exc
    current = time.time() if now is None else float(now)
    if issued > current + MAX_FUTURE_SKEW_SECONDS or current - issued > MAX_AGE_SECONDS:
        raise AssertionError("operator assertion expired or not yet valid")
    if payload["method"] != method.upper() or payload["path"] != path:
        raise AssertionError("operator assertion request binding mismatch")
    if payload["tenant_id"] != tenant_id:
        raise AssertionError("operator assertion tenant mismatch")

    db_path = Path(replay_db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(str(db_path), timeout=5.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS operator_assertion_nonces (
                nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL
            )""")
            conn.execute("DELETE FROM operator_assertion_nonces WHERE expires_at < ?", (int(current),))
            conn.execute(
                "INSERT INTO operator_assertion_nonces(nonce, expires_at) VALUES (?, ?)",
                (payload["nonce"], issued + MAX_AGE_SECONDS + MAX_FUTURE_SKEW_SECONDS),
            )
    except sqlite3.IntegrityError as exc:
        raise AssertionError("operator assertion replay detected") from exc
    except sqlite3.Error as exc:
        raise AssertionError("operator assertion replay store unavailable") from exc
    return payload
