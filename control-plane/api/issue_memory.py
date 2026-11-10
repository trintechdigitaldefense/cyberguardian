"""Crash-safe persistent issue memory — bounded JSONL, no synthetic events."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Dict, List, Optional

from runtime_paths import DATA_DIR

STORE = DATA_DIR / "issue_memory.jsonl"
_DEFAULT_ARCHIVE = DATA_DIR / "issue_memory_archive.jsonl"
ARCHIVE = _DEFAULT_ARCHIVE
MAX_ISSUES = 2000
MAX_ARCHIVED_ISSUES = 10000
_CURRENT_TENANT = ContextVar("cg_issue_memory_tenant", default=None)


def set_current_tenant(tenant_id: Optional[str]):
    value = str(tenant_id or "").strip() or None
    return _CURRENT_TENANT.set(value)


def reset_current_tenant(token) -> None:
    _CURRENT_TENANT.reset(token)


def current_tenant_id() -> Optional[str]:
    value = _CURRENT_TENANT.get()
    return str(value).strip() if value else None


def _production_mode() -> bool:
    return (
        os.environ.get("CG_PRODUCTION", "0").strip().lower() in {"1", "true", "yes", "on"}
        or os.environ.get("CG_REQUIRE_AGENT_IDENTITY", "0").strip().lower() in {"1", "true", "yes", "on"}
    )


def _effective_tenant(tenant_id: Optional[str]) -> Optional[str]:
    value = str(tenant_id or current_tenant_id() or "").strip()
    if not value and _production_mode():
        raise PermissionError("tenant context is required for issue-memory access")
    return value or None


class IssueMemoryIntegrityError(RuntimeError):
    """Raised when issue-memory JSONL contains malformed evidence."""


class IssueMemoryCapacityError(RuntimeError):
    """Raised when bounded active and archive stores cannot safely accept more data."""


@contextmanager
def _store_lock():
    STORE.parent.mkdir(parents=True, exist_ok=True)
    lock_path = STORE.with_name(STORE.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_all() -> List[Dict[str, Any]]:
    if not STORE.exists():
        return []
    out = []
    with open(STORE, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict) or not item.get("id"):
                    raise ValueError("issue-memory record has an invalid schema")
                out.append(item)
            except (ValueError, TypeError) as exc:
                raise IssueMemoryIntegrityError(
                    f"invalid issue-memory JSON at line {len(out) + 1}"
                ) from exc
    return out


def _archive_path() -> Path:
    # Preserve the configurable archive path used by migration and operations;
    # derive a sibling path for isolated/custom stores unless explicitly overridden.
    if ARCHIVE != _DEFAULT_ARCHIVE:
        return Path(ARCHIVE)
    return STORE.with_name(STORE.stem + "_archive" + STORE.suffix)


def _archive_evicted(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    archive = _archive_path()
    archive.parent.mkdir(parents=True, exist_ok=True)
    known_ids = set()
    count = 0
    if archive.exists():
        with open(archive, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except (ValueError, TypeError) as exc:
                    raise IssueMemoryIntegrityError(
                        f"invalid issue archive JSON at line {line_number}"
                    ) from exc
                if not isinstance(record, dict) or not record.get("id"):
                    raise IssueMemoryIntegrityError(
                        f"invalid issue archive record at line {line_number}"
                    )
                known_ids.add(str(record["id"]))
                count += 1
    pending = []
    for original in items:
        issue_id = str(original.get("id") or "")
        if issue_id and issue_id not in known_ids:
            archived = dict(original)
            archived["archived_at"] = time.time()
            archived["archive_reason"] = "active_store_capacity"
            pending.append(archived)
            known_ids.add(issue_id)
    if count + len(pending) > MAX_ARCHIVED_ISSUES:
        raise IssueMemoryCapacityError(
            "issue archive is full; refusing to discard older issue evidence"
        )
    if not pending:
        return
    fd = os.open(archive, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
        for item in pending:
            encoded = json.dumps(item, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short append to issue archive")
                view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(archive, 0o600)
    dir_fd = os.open(str(archive.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _write_all(items: List[Dict[str, Any]]) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    if len(items) > MAX_ISSUES:
        _archive_evicted(items[:-MAX_ISSUES])
    fd, temp_name = tempfile.mkstemp(prefix=STORE.name + ".", suffix=".tmp", dir=str(STORE.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for item in items[-MAX_ISSUES:]:
                handle.write(json.dumps(item, separators=(",", ":"), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, STORE)
        os.chmod(STORE, 0o600)
        dir_fd = os.open(str(STORE.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def list_archived_issues(
    limit: int = MAX_ARCHIVED_ISSUES, tenant_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    try:
        tenant = _effective_tenant(tenant_id)
    except PermissionError:
        return []
    archive = _archive_path()
    if not archive.exists():
        return []
    out = []
    with open(archive, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except (ValueError, TypeError) as exc:
                raise IssueMemoryIntegrityError(
                    f"invalid issue archive JSON at line {line_number}"
                ) from exc
            if not isinstance(item, dict):
                raise IssueMemoryIntegrityError(
                    f"invalid issue archive record at line {line_number}"
                )
            if tenant is None or str(item.get("tenant_id") or "") == tenant:
                out.append(item)
    return out[-max(0, min(int(limit), MAX_ARCHIVED_ISSUES)):]

def fingerprint(title: str, asset_id: str, tags=None, tenant_id: str = "default") -> str:
    tags = tags or []
    raw = f"{tenant_id}|{asset_id}|{title.strip().lower()}|{'|'.join(sorted(str(t).lower() for t in tags))}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _write_archive_all(items: List[Dict[str, Any]]) -> None:
    archive = _archive_path()
    archive.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=archive.name + ".", suffix=".tmp", dir=str(archive.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for item in items:
                handle.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, archive)
        os.chmod(archive, 0o600)
        dir_fd = os.open(str(archive.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def migrate_legacy_tenant_ids(asset_tenant_lookup) -> Dict[str, Any]:
    """Backfill tenant IDs for legacy active and archived issues using the asset registry."""
    with _store_lock():
        active = _read_all()
        archive_path = _archive_path()
        archived: List[Dict[str, Any]] = []
        if archive_path.exists():
            with open(archive_path, "r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                    except (ValueError, TypeError) as exc:
                        raise IssueMemoryIntegrityError(
                            f"invalid issue archive JSON at line {line_number}"
                        ) from exc
                    if not isinstance(item, dict) or not item.get("id"):
                        raise IssueMemoryIntegrityError(
                            f"invalid issue archive record at line {line_number}"
                        )
                    archived.append(item)

        migrated_active = 0
        migrated_archived = 0
        unresolved: List[str] = []
        for collection, counter in ((active, "active"), (archived, "archived")):
            for item in collection:
                if str(item.get("tenant_id") or "").strip():
                    continue
                asset_id = str(item.get("asset_id") or "").strip()
                tenant = asset_tenant_lookup(asset_id) if asset_id else None
                if tenant:
                    item["tenant_id"] = str(tenant)
                    if counter == "active":
                        migrated_active += 1
                    else:
                        migrated_archived += 1
                else:
                    unresolved.append(str(item.get("id") or "unknown"))
        if migrated_archived:
            _write_archive_all(archived)
        if migrated_active:
            _write_all(active)
        return {
            "active_migrated": migrated_active,
            "archived_migrated": migrated_archived,
            "unresolved": unresolved,
        }


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
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    tenant = _effective_tenant(tenant_id) or "default"
    with _store_lock():
        tags = tags or []
        fp = fingerprint(title, asset_id, tags, tenant)
        items = _read_all()
        now = time.time()
        for item in items:
            if item.get("fingerprint") == fp and item.get("status") in ("open", "watching", "staged"):
                item["last_seen"] = now
                item["seen_count"] = int(item.get("seen_count") or 1) + 1
                item["severity"] = severity or item.get("severity")
                if indicators:
                    item["indicators"] = indicators
                if detection_id:
                    item["last_detection_id"] = detection_id
                _write_all(items)
                return item
        record = {
            "id": str(uuid.uuid4()),
            "fingerprint": fp,
            "title": title,
            "asset_id": asset_id,
            "tenant_id": tenant,
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
            or any(t in tags for t in ("credential_access", "ransomware", "malware", "c2", "suspicious_process")),
            "notes": [],
        }
        items.append(record)
        _write_all(items)
        return record


def list_issues(
    status: Optional[str] = None,
    limit: int = 100,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    try:
        tenant = _effective_tenant(tenant_id)
    except PermissionError:
        return []
    items = _read_all()
    if tenant is not None:
        items = [item for item in items if str(item.get("tenant_id") or "") == tenant]
    items.sort(key=lambda item: item.get("last_seen") or 0, reverse=True)
    if status:
        items = [item for item in items if item.get("status") == status]
    return items[:max(0, min(int(limit), MAX_ISSUES))]


def update_issue(
    issue_id: str, tenant_id: Optional[str] = None, **fields
) -> Optional[Dict[str, Any]]:
    try:
        tenant = _effective_tenant(tenant_id)
    except PermissionError:
        return None
    fields.pop("tenant_id", None)
    with _store_lock():
        items = _read_all()
        for item in items:
            if item.get("id") == issue_id and (
                tenant is None or str(item.get("tenant_id") or "") == tenant
            ):
                item.update({key: value for key, value in fields.items() if value is not None})
                item["updated_at"] = time.time()
                _write_all(items)
                return item
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
