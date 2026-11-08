"""Per-agent credentials stored only on the controller, never in Git."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from runtime_paths import DATA_DIR

STORE = DATA_DIR / "agent_credentials.json"


def load_agent_credentials() -> Dict[str, Dict[str, Any]]:
    if not STORE.exists():
        return {}
    try:
        raw = json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    agents = raw.get("agents", {}) if isinstance(raw, dict) else {}
    return agents if isinstance(agents, dict) else {}


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
        if isinstance(rec, dict) and rec.get("status", "active") == "active":
            if str(rec.get("api_key") or "") == api_key:
                return asset_id, dict(rec)
    return None


def active_agent_api_keys() -> set[str]:
    return {
        str(rec.get("api_key"))
        for rec in load_agent_credentials().values()
        if isinstance(rec, dict) and rec.get("status", "active") == "active" and rec.get("api_key")
    }


def write_agent_credentials(agents: Dict[str, Dict[str, Any]]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
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
    finally:
        try:
            if os.path.exists(name):
                os.unlink(name)
        except OSError:
            pass
