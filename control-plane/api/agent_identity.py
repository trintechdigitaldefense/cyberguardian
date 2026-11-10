"""Per-agent signed identity and registration checks."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

from runtime_paths import DATA_DIR
from agent_credentials import get_agent_credential, find_agent_by_api_key

DATA = DATA_DIR
CREDS = DATA / "credentials.json"
FINGERPRINTS = DATA / "agent_fingerprints.json"


def _load_creds() -> dict:
    if CREDS.exists():
        try:
            value = json.loads(CREDS.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            pass
    return {}


def production_mode() -> bool:
    flags = ("CG_PRODUCTION", "CG_REQUIRE_AGENT_IDENTITY")
    if any((os.environ.get(name) or "").lower() in ("1", "true", "yes") for name in flags):
        return True
    return bool(_load_creds().get("require_agent_identity"))


def identity_secret(asset_id: Optional[str] = None) -> str:
    if asset_id:
        rec = get_agent_credential(asset_id)
        if rec:
            return str(rec.get("identity_secret") or "").strip()
        if production_mode():
            return ""
    creds = _load_creds()
    return str(creds.get("agent_identity_secret") or os.environ.get("CG_AGENT_IDENTITY_SECRET") or "").strip()


def host_fingerprint(hostname: str, os_info: str = "", machine_id: str = "") -> str:
    raw = f"{hostname}|{os_info}|{machine_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def sign_registration(asset_id: str, fingerprint: str, ts: float, secret: Optional[str] = None) -> str:
    key = secret if secret is not None else identity_secret(asset_id)
    if not key:
        return ""
    message = f"{asset_id}|{fingerprint}|{int(ts)}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_registration(
    asset_id: str,
    fingerprint: str,
    ts: float,
    signature: str,
    max_age_seconds: int = 600,
) -> tuple[bool, str]:
    if not asset_id or not fingerprint or not signature:
        return False, "missing_identity_fields"
    secret = identity_secret(asset_id)
    if not secret:
        if production_mode():
            return False, "agent_identity_secret_required"
        return True, "identity_secret_unset_skip_lab"
    try:
        timestamp = float(ts)
    except (TypeError, ValueError):
        return False, "invalid_identity_timestamp"
    now = time.time()
    if timestamp <= 0 or abs(now - timestamp) > max_age_seconds:
        return False, "identity_signature_expired"
    expected = sign_registration(asset_id, fingerprint, timestamp, secret)
    if not hmac.compare_digest(expected, str(signature)):
        return False, "bad_identity_signature"
    return True, "ok"


def assert_not_admin_key_on_agent(api_key: str) -> tuple[bool, str]:
    admin = str(_load_creds().get("api_key") or os.environ.get("CYBERGUARDIAN_API_KEY") or "").strip()
    if not api_key or (admin and hmac.compare_digest(api_key, admin)):
        return False, "admin_key_not_allowed_for_agent"
    match = find_agent_by_api_key(api_key)
    if match:
        return True, "per_agent_key"
    legacy = str(_load_creds().get("agent_api_key") or "").strip()
    if not production_mode() and legacy and hmac.compare_digest(api_key, legacy):
        return True, "legacy_lab_agent_key"
    return False, "unknown_or_revoked_agent_key"


def _read_fingerprints_unlocked() -> Dict[str, Any]:
    if not FINGERPRINTS.exists():
        return {}
    try:
        value = json.loads(FINGERPRINTS.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("agent fingerprint store is unreadable; refusing identity update") from exc
    if not isinstance(value, dict) or any(not isinstance(item, dict) for item in value.values()):
        raise RuntimeError("agent fingerprint store has an invalid schema")
    return value


def load_fingerprints() -> Dict[str, Any]:
    return _read_fingerprints_unlocked()


def remember_fingerprint(asset_id: str, fingerprint: str, hostname: str = "") -> None:
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    DATA.chmod(0o700)
    lock_path = FINGERPRINTS.with_suffix(".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        data = _read_fingerprints_unlocked()
        previous = data.get(asset_id)
        data[asset_id] = {
            "fingerprint": fingerprint,
            "hostname": hostname,
            "first_seen": (previous or {}).get("first_seen") or time.time(),
            "last_seen": time.time(),
            "previous": (
                (previous or {}).get("fingerprint")
                if previous and previous.get("fingerprint") != fingerprint
                else (previous or {}).get("previous")
            ),
        }
        fd, temporary = tempfile.mkstemp(prefix=".agent_fingerprints.", dir=str(FINGERPRINTS.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, FINGERPRINTS)
            FINGERPRINTS.chmod(0o600)
            dir_fd = os.open(FINGERPRINTS.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            except OSError:
                pass
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def check_fingerprint_change(asset_id: str, fingerprint: str) -> Optional[str]:
    previous = load_fingerprints().get(asset_id)
    if previous and previous.get("fingerprint") and previous["fingerprint"] != fingerprint:
        return f"fingerprint_changed from {previous['fingerprint'][:8]}… to {fingerprint[:8]}…"
    return None
