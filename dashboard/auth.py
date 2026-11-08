"""Persistent dashboard authentication primitives for CyberGuardian R3."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

DATA_DIR = Path(os.getenv("CG_DATA_DIR") or (Path(__file__).resolve().parents[1] / "data"))
CREDS_PATH = DATA_DIR / "credentials.json"
AUTH_DB = Path(os.getenv("CG_AUTH_DB") or (DATA_DIR / "dashboard_auth.sqlite3"))
SESSION_TTL_SECONDS = max(300, int(os.getenv("CG_SESSION_TTL_SECONDS", "28800")))
LOGIN_WINDOW_SECONDS = max(60, int(os.getenv("CG_LOGIN_WINDOW_SECONDS", "900")))
MAX_LOGIN_FAILURES = max(3, int(os.getenv("CG_LOGIN_MAX_FAILURES", "5")))
PBKDF2_ITERATIONS = 310_000
PRODUCTION = os.getenv("CG_PRODUCTION", "0").strip().lower() in {"1", "true", "yes", "on"}


def _connect() -> sqlite3.Connection:
    AUTH_DB.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        AUTH_DB.parent.chmod(0o700)
    except OSError:
        pass
    conn = sqlite3.connect(str(AUTH_DB), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def init_auth_store() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS dashboard_sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                role TEXT NOT NULL,
                csrf_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_expiry
                ON dashboard_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS dashboard_login_attempts (
                attempt_key TEXT NOT NULL,
                attempted_at REAL NOT NULL,
                success INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_dashboard_login_attempts_key_time
                ON dashboard_login_attempts(attempt_key, attempted_at);
            """
        )
    try:
        AUTH_DB.chmod(0o600)
    except OSError:
        pass


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    if not isinstance(password, str) or len(password) < 10:
        raise ValueError("password must contain at least 10 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return "pbkdf2_sha256" + "$" + str(iterations) + "$" + salt_b64 + "$" + digest_b64


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_text, digest_text = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(rounds)
        if iterations < 100_000 or iterations > 2_000_000:
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError):
        hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), b"cyberguardian-invalid-salt", 100_000)
        return False


def _read_credentials() -> Dict[str, Any]:
    try:
        value = json.loads(CREDS_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}


def _write_credentials_atomic(value: Dict[str, Any]) -> None:
    CREDS_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".credentials.", dir=str(CREDS_PATH.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, CREDS_PATH)
        CREDS_PATH.chmod(0o600)
    finally:
        try:
            if os.path.exists(name):
                os.unlink(name)
        except OSError:
            pass


def get_user(username: str) -> Optional[Dict[str, str]]:
    credentials = _read_credentials()
    users = credentials.get("users")
    if isinstance(users, dict):
        record = users.get(username)
        if isinstance(record, dict):
            return {
                "username": username,
                "password_hash": str(record.get("password_hash") or ""),
                "legacy_password": "",
                "tenant_id": str(record.get("tenant_id") or "default"),
                "role": str(record.get("role") or "admin"),
            }
    admin_user = str(credentials.get("admin_user") or "cyberguardian")
    if username != admin_user:
        return None
    password_hash = str(credentials.get("admin_password_hash") or os.getenv("CG_ADMIN_PASSWORD_HASH") or "")
    legacy_password = str(credentials.get("admin_password") or "")
    if not password_hash and not legacy_password and not PRODUCTION:
        legacy_password = os.getenv("CG_ADMIN_PASSWORD", "")
    return {
        "username": admin_user,
        "password_hash": password_hash,
        "legacy_password": legacy_password,
        "tenant_id": "default",
        "role": "admin",
    }


def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    user = get_user(username)
    if not user:
        hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b"cyberguardian-unknown-user", 100_000)
        return None
    encoded = user.get("password_hash") or ""
    if encoded and verify_password(password, encoded):
        return user
    legacy = user.get("legacy_password") or ""
    if legacy and not PRODUCTION and hmac.compare_digest(password, legacy):
        raw = _read_credentials()
        if raw.get("admin_user") == username and raw.get("admin_password"):
            raw["admin_password_hash"] = hash_password(password)
            raw.pop("admin_password", None)
            _write_credentials_atomic(raw)
            user["password_hash"] = raw["admin_password_hash"]
        user["legacy_password"] = ""
        return user
    return None


def _attempt_key(client_ip: str, username: str) -> str:
    value = f"{client_ip.strip()}|{username.strip().casefold()}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def is_rate_limited(client_ip: str, username: str, now: Optional[float] = None) -> bool:
    current = time.time() if now is None else float(now)
    key = _attempt_key(client_ip, username)
    with _connect() as conn:
        conn.execute("DELETE FROM dashboard_login_attempts WHERE attempted_at < ?", (current - LOGIN_WINDOW_SECONDS,))
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM dashboard_login_attempts WHERE attempt_key=? AND success=0 AND attempted_at>=?",
            (key, current - LOGIN_WINDOW_SECONDS),
        ).fetchone()
    return int(row["n"] if row else 0) >= MAX_LOGIN_FAILURES


def record_login_attempt(client_ip: str, username: str, success: bool, now: Optional[float] = None) -> None:
    current = time.time() if now is None else float(now)
    key = _attempt_key(client_ip, username)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO dashboard_login_attempts(attempt_key, attempted_at, success) VALUES (?, ?, ?)",
            (key, current, 1 if success else 0),
        )
        conn.execute("DELETE FROM dashboard_login_attempts WHERE attempted_at < ?", (current - LOGIN_WINDOW_SECONDS,))
        if success:
            conn.execute("DELETE FROM dashboard_login_attempts WHERE attempt_key=?", (key,))


def create_session(user: Dict[str, str], now: Optional[float] = None) -> tuple[str, str, float]:
    current = time.time() if now is None else float(now)
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    csrf_hash = hashlib.sha256(csrf.encode("utf-8")).hexdigest()
    expires = current + SESSION_TTL_SECONDS
    with _connect() as conn:
        conn.execute("DELETE FROM dashboard_sessions WHERE expires_at<=? OR revoked_at IS NOT NULL", (current,))
        conn.execute(
            """INSERT INTO dashboard_sessions
               (token_hash, username, tenant_id, role, csrf_hash, created_at, expires_at, revoked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
            (token_hash, user["username"], user.get("tenant_id") or "default",
             user.get("role") or "admin", csrf_hash, current, expires),
        )
    return token, csrf, expires


def get_session(token: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    current = time.time() if now is None else float(now)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _connect() as conn:
        row = conn.execute(
            """SELECT username, tenant_id, role, csrf_hash, created_at, expires_at
               FROM dashboard_sessions
               WHERE token_hash=? AND revoked_at IS NULL AND expires_at>?""",
            (token_hash, current),
        ).fetchone()
    return dict(row) if row else None


def verify_csrf(session: Dict[str, Any], csrf_token: str) -> bool:
    if not session or not csrf_token:
        return False
    supplied = hashlib.sha256(csrf_token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(supplied, str(session.get("csrf_hash") or ""))


def revoke_session(token: str) -> bool:
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE dashboard_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
            (time.time(), token_hash),
        )
    return cur.rowcount == 1


init_auth_store()
