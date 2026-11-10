"""Per-agent credentials stored only on the controller, never in Git."""
from __future__ import annotations

import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from runtime_paths import DATA_DIR

STORE = DATA_DIR / "agent_credentials.json"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _validate_agent_registry(agents: Dict[str, Dict[str, Any]]) -> None:
    if not isinstance(agents, dict):
        raise RuntimeError("agent credential store has an invalid schema")
    seen_secrets: set[str] = set()
    for asset_id, record in agents.items():
        if not isinstance(asset_id, str) or not _IDENTIFIER.fullmatch(asset_id):
            raise RuntimeError("agent credential store contains an invalid asset ID")
        if not isinstance(record, dict):
            raise RuntimeError("agent credential store contains an invalid enrollment record")
        tenant_id = str(record.get("tenant_id") or "").strip()
        status = str(record.get("status") or "active").strip().lower()
        if not tenant_id or not _IDENTIFIER.fullmatch(tenant_id):
            raise RuntimeError(f"agent enrollment {asset_id} has an invalid tenant ID")
        if status not in {"active", "revoked"}:
            raise RuntimeError(f"agent enrollment {asset_id} has an invalid status")
        if status == "revoked":
            continue
        secrets_for_agent = [
            str(record.get(field) or "").strip()
            for field in ("api_key", "identity_secret", "command_secret")
        ]
        if any(len(value.encode("utf-8")) < 32 for value in secrets_for_agent):
            raise RuntimeError(f"active agent enrollment {asset_id} has weak or missing credentials")
        if len(set(secrets_for_agent)) != len(secrets_for_agent):
            raise RuntimeError(f"active agent enrollment {asset_id} reuses a credential")
        for value in secrets_for_agent:
            if value in seen_secrets:
                raise RuntimeError("active agent enrollments must not share credentials")
            seen_secrets.add(value)


def load_agent_credentials() -> Dict[str, Dict[str, Any]]:
    """Load the enrollment registry; never treat corruption as an empty registry."""
    if not STORE.exists():
        return {}
    try:
        raw = json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError(
            "agent credential store is unreadable; refusing to continue"
        ) from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("agents"), dict):
        raise RuntimeError("agent credential store has an invalid schema")
    agents = raw["agents"]
    _validate_agent_registry(agents)
    return agents


def get_agent_credential(asset_id: str, *, include_revoked: bool = False) -> Optional[Dict[str, Any]]:
    rec = load_agent_credentials().get(str(asset_id))
    if not isinstance(rec, dict):
        return None
    if not include_revoked and rec.get("status", "active") != "active":
        return None
    return dict(rec)


def find_agent_by_api_key(api_key: str) -> Optional[tuple[str, Dict[str, Any]]]:
    if not api_key:
        return None
    for asset_id, rec in load_agent_credentials().items():
        stored_key = str(rec.get("api_key") or "")
        if rec.get("status", "active") == "active" and stored_key:
            if hmac.compare_digest(stored_key, api_key):
                return asset_id, dict(rec)
    return None


def active_agent_api_keys() -> set[str]:
    return {
        str(rec.get("api_key"))
        for rec in load_agent_credentials().values()
        if rec.get("status", "active") == "active" and rec.get("api_key")
    }


def write_agent_credentials(agents: Dict[str, Dict[str, Any]]) -> None:
    _validate_agent_registry(agents)
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    DATA_DIR.chmod(0o700)
    payload = json.dumps({"agents": agents}, indent=2, sort_keys=True)
    fd, name = tempfile.mkstemp(prefix=".agent_credentials.", dir=str(DATA_DIR))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, STORE)
        STORE.chmod(0o600)
        dir_fd = os.open(DATA_DIR, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            if os.path.exists(name):
                os.unlink(name)
        except OSError:
            pass
