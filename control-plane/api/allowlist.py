"""Safe auto-remediate allowlist — Tier 2."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Set

ROOT = Path(__file__).resolve().parents[2]
CFG_PATH = ROOT / "configs" / "auto_allowlist.yaml"
DATA_OVERRIDE = ROOT / "data" / "auto_allowlist.json"


def _parse_simple_yaml(text: str) -> dict:
    """Minimal YAML subset parser (no PyYAML required)."""
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass
    out: dict = {}
    current_list = None
    for line in text.splitlines():
        raw = line.split("#")[0].rstrip()
        if not raw.strip():
            continue
        if raw.startswith(" ") and current_list is not None:
            item = raw.strip().lstrip("-").strip()
            if item:
                out.setdefault(current_list, []).append(item)
            continue
        if ":" in raw and not raw.strip().startswith("-"):
            key, _, val = raw.partition(":")
            key = key.strip()
            val = val.strip()
            if val.lower() in ("true", "false"):
                out[key] = val.lower() == "true"
                current_list = None
            elif val:
                out[key] = val
                current_list = None
            else:
                out[key] = []
                current_list = key
    return out


def load_allowlist() -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "enabled": True,
        "allowed_asset_tags": ["lab", "dev", "staging", "dry-run"],
        "allowed_playbooks": ["credential_theft", "ransomware", "c2_beacon"],
        "allowed_actions": ["alert_only", "kill_process", "block_ip"],
        "deny_asset_tags": ["production", "prod", "client", "critical"],
    }
    if CFG_PATH.exists():
        try:
            loaded = _parse_simple_yaml(CFG_PATH.read_text()) or {}
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except Exception:
            pass
    if DATA_OVERRIDE.exists():
        try:
            loaded = json.loads(DATA_OVERRIDE.read_text())
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except Exception:
            pass
    return cfg


def save_allowlist(cfg: Dict[str, Any]) -> Dict[str, Any]:
    DATA_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
    DATA_OVERRIDE.write_text(json.dumps(cfg, indent=2))
    try:
        DATA_OVERRIDE.chmod(0o600)
    except Exception:
        pass
    return cfg


def asset_tags(tags: Any) -> Set[str]:
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except Exception:
            tags = [tags]
    if not isinstance(tags, list):
        return set()
    return {str(t).lower().strip() for t in tags if t}


def may_auto_remediate(
    *,
    asset_tags_list: Any,
    playbook_id: str,
    action: str,
    client_mode: bool,
) -> tuple[bool, str]:
    if client_mode:
        return False, "client_mode_on"
    cfg = load_allowlist()
    if not cfg.get("enabled", True):
        return False, "allowlist_disabled"
    tags = asset_tags(asset_tags_list)
    deny = {str(t).lower() for t in (cfg.get("deny_asset_tags") or [])}
    if tags & deny:
        return False, f"deny_tag:{','.join(sorted(tags & deny))}"
    allowed_tags = {str(t).lower() for t in (cfg.get("allowed_asset_tags") or [])}
    if not (tags & allowed_tags):
        return False, "asset_not_allowlisted"
    allowed_pb = {str(p).lower() for p in (cfg.get("allowed_playbooks") or [])}
    if playbook_id and str(playbook_id).lower() not in allowed_pb:
        return False, f"playbook_not_allowed:{playbook_id}"
    if not playbook_id:
        return False, "no_playbook"
    allowed_act = {str(a).lower() for a in (cfg.get("allowed_actions") or [])}
    if str(action).lower() not in allowed_act:
        return False, f"action_not_allowed:{action}"
    return True, "allowlist_match"
