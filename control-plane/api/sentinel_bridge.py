"""
Sentinel bridge — optional handoff between CyberGuardian (fleet control plane)
and Sentinel (single-host line of defense). Tier 2.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
CFG = DATA / "sentinel_bridge.json"


def load_cfg() -> Dict[str, Any]:
    default = {
        "enabled": False,
        "sentinel_url": os.environ.get("SENTINEL_URL", "http://127.0.0.1:8787"),
        "sentinel_api_key": os.environ.get("SENTINEL_API_KEY", ""),
        "push_on_approve": True,
        "timeout_seconds": 5,
    }
    if CFG.exists():
        try:
            default.update(json.loads(CFG.read_text()))
        except Exception:
            pass
    return default


def save_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    DATA.mkdir(parents=True, exist_ok=True)
    CFG.write_text(json.dumps(cfg, indent=2))
    try:
        CFG.chmod(0o600)
    except Exception:
        pass
    return cfg


def _request(method: str, path: str, body: Optional[dict] = None) -> Dict[str, Any]:
    cfg = load_cfg()
    if not cfg.get("enabled"):
        return {"ok": False, "skipped": True, "reason": "bridge_disabled"}
    url = cfg["sentinel_url"].rstrip("/") + path
    data = None
    headers = {"Accept": "application/json", "User-Agent": "CyberGuardian-SentinelBridge/1.0"}
    key = (cfg.get("sentinel_api_key") or "").strip()
    if key:
        headers["X-API-Key"] = key
        headers["Authorization"] = f"Bearer {key}"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=int(cfg.get("timeout_seconds") or 5)) as resp:
            raw = resp.read().decode()
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"raw": raw}
            return {"ok": True, "status": resp.status, "body": parsed}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def health() -> Dict[str, Any]:
    cfg = load_cfg()
    if not cfg.get("enabled"):
        return {"enabled": False, "reachable": False, "note": "Enable via POST /v1/sentinel/config"}
    result = _request("GET", "/health")
    return {
        "enabled": True,
        "sentinel_url": cfg.get("sentinel_url"),
        "reachable": bool(result.get("ok")),
        "result": result,
    }


def push_containment_hint(
    *,
    asset_id: str,
    action: str,
    target: str,
    reason: str = "",
    detection_id: str = "",
) -> Dict[str, Any]:
    cfg = load_cfg()
    if not cfg.get("enabled") or not cfg.get("push_on_approve", True):
        return {"ok": False, "skipped": True, "reason": "bridge_off_or_push_disabled"}
    payload = {
        "source": "cyberguardian",
        "asset_id": asset_id,
        "action": action,
        "target": target,
        "reason": reason,
        "detection_id": detection_id,
        "ts": time.time(),
    }
    last = {}
    for path in ("/v1/handoff", "/api/handoff", "/v1/alerts", "/alert"):
        result = _request("POST", path, payload)
        last = result
        if result.get("ok"):
            return {"ok": True, "path": path, "result": result}
    return {"ok": False, "error": "no_handoff_endpoint_accepted", "last": last}


def status_summary() -> Dict[str, Any]:
    cfg = load_cfg()
    h = health()
    return {
        "bridge": {
            "enabled": bool(cfg.get("enabled")),
            "sentinel_url": cfg.get("sentinel_url"),
            "push_on_approve": bool(cfg.get("push_on_approve", True)),
        },
        "health": h,
        "positioning": {
            "cyberguardian": "fleet control plane — detect, decide, approve, audit",
            "sentinel": "single-host line of defense — deception, FIM, local blocking",
        },
    }
