"""Persistent issue memory — disk JSONL, no fake events."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# __file__ = .../CyberGuardian/control-plane/api/issue_memory.py → parents[2] = repo root
STORE = Path(__file__).resolve().parents[2] / "data" / "issue_memory.jsonl"
if not STORE.parent.exists():
    STORE = Path("/tmp/cyberguardian_issue_memory.jsonl")


def _read_all() -> List[Dict[str, Any]]:
    if not STORE.exists():
        return []
    out = []
    for line in STORE.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _write_all(items: List[Dict[str, Any]]) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    with open(STORE, "w") as f:
        for it in items[-2000:]:
            f.write(json.dumps(it, separators=(",", ":")) + "\n")


def fingerprint(title: str, asset_id: str, tags=None) -> str:
    tags = tags or []
    raw = f"{asset_id}|{title.strip().lower()}|{'|'.join(sorted(str(t).lower() for t in tags))}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def remember_issue(
    title: str,
    asset_id: str,
    severity: str = "medium",
    source: str = "agent",
    tags: Optional[List[str]] = None,
    indicators: Optional[Dict] = None,
    description: str = "",
    detection_id: str = "",
    playbook_id: str = "",
) -> Dict[str, Any]:
    tags = tags or []
    fp = fingerprint(title, asset_id, tags)
    items = _read_all()
    now = time.time()
    for it in items:
        if it.get("fingerprint") == fp and it.get("status") in ("open", "watching", "staged"):
            it["last_seen"] = now
            it["seen_count"] = int(it.get("seen_count") or 1) + 1
            it["severity"] = severity or it.get("severity")
            if indicators:
                it["indicators"] = indicators
            if detection_id:
                it["last_detection_id"] = detection_id
            _write_all(items)
            return it
    rec = {
        "id": str(uuid.uuid4()),
        "fingerprint": fp,
        "title": title,
        "asset_id": asset_id,
        "severity": severity,
        "source": source,
        "tags": tags,
        "indicators": indicators or {},
        "description": description,
        "playbook_id": playbook_id or "",
        "status": "open",
        "seen_count": 1,
        "first_seen": now,
        "last_seen": now,
        "last_detection_id": detection_id or "",
        "auto_fix_eligible": bool(playbook_id)
        or any(
            t in (tags or [])
            for t in ("credential_access", "ransomware", "malware", "c2", "suspicious_process")
        ),
        "notes": [],
    }
    items.append(rec)
    _write_all(items)
    return rec


def list_issues(status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    items = _read_all()
    items.sort(key=lambda x: x.get("last_seen") or 0, reverse=True)
    if status:
        items = [i for i in items if i.get("status") == status]
    return items[:limit]


def update_issue(issue_id: str, **fields) -> Optional[Dict[str, Any]]:
    items = _read_all()
    for it in items:
        if it.get("id") == issue_id:
            it.update({k: v for k, v in fields.items() if v is not None})
            it["updated_at"] = time.time()
            _write_all(items)
            return it
    return None


def known_auto_actions(issue: Dict[str, Any]) -> List[Dict[str, str]]:
    tags = set(str(t).lower() for t in (issue.get("tags") or []))
    title = (issue.get("title") or "").lower()
    actions = []
    pid = str(
        (issue.get("indicators") or {}).get("pid")
        or (issue.get("indicators") or {}).get("process_id")
        or ""
    )
    asset = issue.get("asset_id") or ""
    if "credential_access" in tags or "mimikatz" in title or "lsass" in title:
        if pid:
            actions.append({"action": "kill_process", "target": pid, "reason": "Credential-theft pattern"})
        actions.append({"action": "isolate_host", "target": asset, "reason": "Contain host"})
    elif "ransomware" in tags or "encrypt" in title:
        actions.append({"action": "isolate_host", "target": asset, "reason": "Ransomware pattern"})
        if pid:
            actions.append({"action": "kill_process", "target": pid, "reason": "Stop encryptor"})
    elif "c2" in tags or "beacon" in title:
        actions.append({"action": "isolate_host", "target": asset, "reason": "C2/beacon pattern"})
    elif pid:
        actions.append({"action": "kill_process", "target": pid, "reason": "Suspicious process"})
    else:
        actions.append({"action": "alert_only", "target": asset, "reason": "No safe auto action"})
    return actions
