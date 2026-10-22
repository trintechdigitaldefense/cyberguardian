"""False-positive feedback — suppress restaging of known-benign fingerprints (Tier 3)."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
STORE = DATA / "false_positives.json"
DEFAULT_SUPPRESS_DAYS = 14


def _load() -> Dict[str, Any]:
    if STORE.exists():
        try:
            return json.loads(STORE.read_text())
        except Exception:
            pass
    return {"items": {}}


def _save(data: Dict[str, Any]) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(data, indent=2))
    try:
        STORE.chmod(0o600)
    except Exception:
        pass


def fingerprint_key(
    title: str = "",
    asset_id: str = "",
    indicators: Optional[dict] = None,
    tags: Optional[list] = None,
) -> str:
    ind = indicators or {}
    bits = [
        (title or "").lower().strip()[:120],
        (asset_id or "").lower().strip(),
        str(ind.get("pid") or ""),
        str(ind.get("cmdline") or ind.get("path") or "")[:80].lower(),
        ",".join(sorted(str(t).lower() for t in (tags or [])[:8])),
    ]
    return hashlib.sha256("|".join(bits).encode()).hexdigest()[:24]


def mark_benign(
    *,
    title: str,
    asset_id: str = "",
    indicators: Optional[dict] = None,
    tags: Optional[list] = None,
    note: str = "",
    actor: str = "operator",
    suppress_days: int = DEFAULT_SUPPRESS_DAYS,
    detection_id: str = "",
    pending_action_id: str = "",
) -> Dict[str, Any]:
    key = fingerprint_key(title, asset_id, indicators, tags)
    data = _load()
    items = data.setdefault("items", {})
    now = time.time()
    until = now + max(1, suppress_days) * 86400
    rec = {
        "key": key,
        "title": title,
        "asset_id": asset_id,
        "indicators": indicators or {},
        "tags": tags or [],
        "note": note,
        "actor": actor,
        "detection_id": detection_id,
        "pending_action_id": pending_action_id,
        "marked_at": now,
        "suppress_until": until,
        "suppress_days": suppress_days,
        "status": "benign",
    }
    items[key] = rec
    _save(data)
    return rec


def is_suppressed(
    title: str = "",
    asset_id: str = "",
    indicators: Optional[dict] = None,
    tags: Optional[list] = None,
) -> tuple[bool, Optional[Dict[str, Any]]]:
    key = fingerprint_key(title, asset_id, indicators, tags)
    data = _load()
    rec = (data.get("items") or {}).get(key)
    if not rec:
        return False, None
    if rec.get("status") != "benign":
        return False, rec
    until = float(rec.get("suppress_until") or 0)
    if time.time() > until:
        return False, rec
    return True, rec


def list_feedback(limit: int = 50) -> List[Dict[str, Any]]:
    data = _load()
    items = list((data.get("items") or {}).values())
    items.sort(key=lambda x: x.get("marked_at") or 0, reverse=True)
    return items[:limit]


def clear_feedback(key: str) -> bool:
    data = _load()
    items = data.get("items") or {}
    if key not in items:
        return False
    del items[key]
    _save(data)
    return True
