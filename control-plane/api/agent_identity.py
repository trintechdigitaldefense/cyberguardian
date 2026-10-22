"""Signed agent identity — host fingerprint + registration token (Tier 2)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
CREDS = DATA / "credentials.json"
FINGERPRINTS = DATA / "agent_fingerprints.json"


def _load_creds() -> dict:
    if CREDS.exists():
        try:
            return json.loads(CREDS.read_text())
        except Exception:
            pass
    return {}


def identity_secret() -> str:
    c = _load_creds()
    secret = (c.get("agent_identity_secret") or os.environ.get("CG_AGENT_IDENTITY_SECRET") or "").strip()
    if secret:
        return secret
    agent_key = (c.get("agent_api_key") or "").strip()
    if agent_key:
        return hashlib.sha256(f"cg-identity:{agent_key}".encode()).hexdigest()
    return ""


def host_fingerprint(hostname: str, os_info: str = "", machine_id: str = "") -> str:
    raw = f"{hostname}|{os_info}|{machine_id}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def sign_registration(asset_id: str, fingerprint: str, ts: float) -> str:
    secret = identity_secret()
    if not secret:
        return ""
    msg = f"{asset_id}|{fingerprint}|{int(ts)}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_registration(
    asset_id: str,
    fingerprint: str,
    ts: float,
    signature: str,
    max_age_seconds: int = 600,
) -> tuple[bool, str]:
    if not signature:
        return False, "missing_signature"
    secret = identity_secret()
    if not secret:
        return True, "identity_secret_unset_skip"
    now = time.time()
    if abs(now - ts) > max_age_seconds:
        return False, "signature_expired"
    expected = sign_registration(asset_id, fingerprint, ts)
    if not hmac.compare_digest(expected, signature):
        return False, "bad_signature"
    return True, "ok"


def load_fingerprints() -> Dict[str, Any]:
    if FINGERPRINTS.exists():
        try:
            return json.loads(FINGERPRINTS.read_text())
        except Exception:
            pass
    return {}


def remember_fingerprint(asset_id: str, fingerprint: str, hostname: str = "") -> None:
    data = load_fingerprints()
    prev = data.get(asset_id)
    data[asset_id] = {
        "fingerprint": fingerprint,
        "hostname": hostname,
        "first_seen": (prev or {}).get("first_seen") or time.time(),
        "last_seen": time.time(),
        "previous": (prev or {}).get("fingerprint") if prev and prev.get("fingerprint") != fingerprint else (prev or {}).get("previous"),
    }
    DATA.mkdir(parents=True, exist_ok=True)
    FINGERPRINTS.write_text(json.dumps(data, indent=2))
    try:
        FINGERPRINTS.chmod(0o600)
    except Exception:
        pass


def check_fingerprint_change(asset_id: str, fingerprint: str) -> Optional[str]:
    data = load_fingerprints()
    prev = data.get(asset_id)
    if not prev:
        return None
    if prev.get("fingerprint") and prev["fingerprint"] != fingerprint:
        return f"fingerprint_changed from {prev['fingerprint'][:8]}… to {fingerprint[:8]}…"
    return None
