"""
File Integrity Monitoring — critical path hashes (Tier strength).
Authorized defensive use only.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

STATE = Path.home() / ".cyberguardian" / "fim_baseline.json"
STATE.parent.mkdir(parents=True, exist_ok=True)

DEFAULT_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/resolv.conf",
]
DEFAULT_GLOBS = ["/etc/cron.d/*", "/etc/sudoers.d/*"]


def _hash_file(path: Path) -> Optional[str]:
    try:
        if not path.is_file():
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


def _expand_targets(extra: Optional[List[str]] = None) -> List[Path]:
    paths: List[Path] = []
    for p in DEFAULT_PATHS + list(extra or []):
        paths.append(Path(p))
    for pattern in DEFAULT_GLOBS:
        parent = Path(pattern).parent
        try:
            if parent.is_dir():
                for child in sorted(parent.iterdir())[:40]:
                    if child.is_file():
                        paths.append(child)
        except (PermissionError, OSError):
            continue
    seen = set()
    out = []
    for p in paths:
        s = str(p)
        if s not in seen:
            seen.add(s)
            out.append(p)
    return out


def load_baseline() -> Dict[str, Any]:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except Exception:
            pass
    return {"files": {}, "created_at": None, "updated_at": None}


def save_baseline(data: Dict[str, Any]) -> None:
    data["updated_at"] = time.time()
    STATE.write_text(json.dumps(data, indent=2))
    try:
        STATE.chmod(0o600)
    except Exception:
        pass


def establish_baseline(extra_paths: Optional[List[str]] = None) -> Dict[str, Any]:
    data = load_baseline()
    files = data.setdefault("files", {})
    now = time.time()
    if not data.get("created_at"):
        data["created_at"] = now
    for path in _expand_targets(extra_paths):
        digest = _hash_file(path)
        key = str(path)
        if digest is None:
            files[key] = {"hash": None, "missing": True, "ts": now}
        else:
            files[key] = {"hash": digest, "missing": False, "ts": now, "size": path.stat().st_size}
    save_baseline(data)
    return data


def scan(extra_paths: Optional[List[str]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    data = load_baseline()
    files = data.get("files") or {}
    if not files:
        data = establish_baseline(extra_paths)
        return [], data
    changes: List[Dict[str, Any]] = []
    current_keys = set()
    for path in _expand_targets(extra_paths):
        key = str(path)
        current_keys.add(key)
        digest = _hash_file(path)
        prev = files.get(key)
        if prev is None:
            if digest is not None:
                changes.append({"type": "created", "path": key, "hash": digest, "severity": "high" if key.startswith("/etc/") else "medium"})
                files[key] = {"hash": digest, "missing": False, "ts": time.time()}
            continue
        if digest is None:
            if not prev.get("missing"):
                changes.append({"type": "deleted_or_unreadable", "path": key, "previous_hash": prev.get("hash"), "severity": "critical" if key in ("/etc/passwd", "/etc/shadow", "/etc/sudoers") else "high"})
            files[key] = {"hash": None, "missing": True, "ts": time.time()}
            continue
        if prev.get("hash") and prev["hash"] != digest:
            changes.append({"type": "modified", "path": key, "previous_hash": prev.get("hash"), "hash": digest, "severity": "critical" if key in ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config") else "high"})
            files[key] = {"hash": digest, "missing": False, "ts": time.time()}
    for key, prev in list(files.items()):
        if key not in current_keys and not prev.get("missing"):
            changes.append({"type": "deleted_or_unreadable", "path": key, "previous_hash": prev.get("hash"), "severity": "high"})
            files[key] = {**prev, "missing": True, "ts": time.time()}
    data["files"] = files
    save_baseline(data)
    return changes, data
