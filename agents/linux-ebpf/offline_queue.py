"""Crash-safe, bounded, single-host offline telemetry queue.

The queue is JSONL for easy inspection, but all mutations are serialized with
an advisory file lock and committed with fsync + atomic replace. A record is
removed only after the delivery callback acknowledges it.
"""
from __future__ import annotations

import fcntl
import hashlib
import inspect
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

QUEUE = Path.home() / ".cyberguardian" / "offline_queue.jsonl"
STATUS = Path.home() / ".cyberguardian" / "connectivity.json"
MAX_LINES = 500
MAX_BYTES = 5 * 1024 * 1024
BASE_BACKOFF_SECONDS = 5
MAX_BACKOFF_SECONDS = 15 * 60


class QueueFullError(RuntimeError):
    """Raised when a new record cannot be accepted without losing queued data."""


def _ensure_private_directory(directory: Path, *, harden_default: bool = False) -> None:
    directory = Path(directory)
    if directory.is_symlink():
        raise PermissionError(f"offline queue directory must not be a symlink: {directory}")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if harden_default:
        os.chmod(directory, 0o700)
    if stat.S_IMODE(directory.stat().st_mode) & 0o077:
        raise PermissionError(f"offline queue directory must be private (0700): {directory}")


class OfflineQueue:
    def __init__(
        self,
        path: Path = QUEUE,
        *,
        max_records: int = MAX_LINES,
        max_bytes: int = MAX_BYTES,
        status_path: Optional[Path] = None,
    ):
        self.path = Path(path)
        self.status_path = Path(status_path) if status_path else self.path.with_name("connectivity.json")
        if self.path.is_symlink() or self.status_path.is_symlink():
            raise PermissionError("offline queue and status files must not be symlinks")
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.flush_lock_path = self.path.with_name(self.path.name + ".flush.lock")
        self.max_records = max(1, int(max_records))
        self.max_bytes = max(1024, int(max_bytes))
        default_queue_dir = Path.home() / ".cyberguardian"
        _ensure_private_directory(
            self.path.parent,
            harden_default=(self.path.parent == default_queue_dir),
        )
        _ensure_private_directory(
            self.status_path.parent,
            harden_default=(self.status_path.parent == default_queue_dir),
        )
        lock_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        for lock_path in (self.lock_path, self.flush_lock_path):
            if lock_path.is_symlink():
                raise PermissionError(f"offline queue lock must not be a symlink: {lock_path}")
            fd = os.open(str(lock_path), lock_flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)

    def _locked(self, lock_path: Optional[Path] = None):
        class Lock:
            def __init__(inner, owner):
                inner.owner = owner
                inner.handle = None
            def __enter__(inner):
                selected = lock_path or inner.owner.lock_path
                if selected.is_symlink():
                    raise PermissionError(f"offline queue lock must not be a symlink: {selected}")
                flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(str(selected), flags, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    inner.handle = os.fdopen(fd, "a+")
                except BaseException:
                    os.close(fd)
                    raise
                fcntl.flock(inner.handle.fileno(), fcntl.LOCK_EX)
                return inner
            def __exit__(inner, exc_type, exc, tb):
                fcntl.flock(inner.handle.fileno(), fcntl.LOCK_UN)
                inner.handle.close()
        return Lock(self)

    def _read_records(self):
        if not self.path.exists():
            return []
        records = []
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if isinstance(record, dict) and record.get("id"):
                        records.append(record)
                    else:
                        raise ValueError("queue record has an invalid schema")
                except (ValueError, TypeError):
                    # Preserve malformed records as opaque failures instead of
                    # silently discarding data during ordinary queue reads.
                    records.append({"id": "corrupt-" + hashlib.sha256(line.encode()).hexdigest(),
                                    "kind": "corrupt", "path": "", "payload": {},
                                    "_corrupt_line": line.rstrip("\n"), "attempts": 0,
                                    "next_attempt_at": 0})
        return records

    def _atomic_write(self, records):
        _ensure_private_directory(self.path.parent, harden_default=(self.path.parent == Path.home() / ".cyberguardian"))
        fd, temp_name = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=str(self.path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            dir_fd = os.open(str(self.path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def _write_status(self, mode: str, queued: int, **extra):
        _ensure_private_directory(self.status_path.parent, harden_default=(self.status_path.parent == Path.home() / ".cyberguardian"))
        data = {"mode": mode, "queued": queued, "ts": time.time(), **extra}
        fd, temp_name = tempfile.mkstemp(prefix=self.status_path.name + ".", suffix=".tmp", dir=str(self.status_path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.status_path)
            try:
                os.chmod(self.status_path, 0o600)
            except OSError:
                pass
            dir_fd = os.open(str(self.status_path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def enqueue(self, kind: str, path: str, payload: Dict[str, Any]) -> int:
        now = time.time()
        canonical = json.dumps(
            {"kind": kind, "path": path, "payload": payload},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        record_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self._locked():
            records = self._read_records()
            if any(item.get("id") == record_id for item in records):
                self._write_status("degraded", len(records), duplicate_suppressed=True)
                return len(records)
            record = {
                "id": record_id, "ts": now, "kind": str(kind),
                "path": str(path), "payload": payload,
                "attempts": 0, "next_attempt_at": 0,
            }
            candidate = records + [record]
            encoded_size = sum(len(json.dumps(item, separators=(",", ":"), sort_keys=True).encode()) + 1
                               for item in candidate)
            if len(candidate) > self.max_records or encoded_size > self.max_bytes:
                self._write_status("degraded", len(records), overflow=True, rejected=1)
                raise QueueFullError("offline queue is full; newest record was rejected to preserve pending data")
            self._atomic_write(candidate)
            self._write_status("degraded", len(candidate))
            return len(candidate)

    def size(self) -> int:
        with self._locked():
            return len(self._read_records())

    def flush(self, post_fn: Callable, *, now: Optional[float] = None, limit: int = 50) -> Dict[str, Any]:
        # Serialize delivery workers with a separate lock while leaving enqueue
        # operations free to acquire the queue data lock during network calls.
        with self._locked(self.flush_lock_path):
            return self._flush_serialized(post_fn, now=now, limit=limit)

    def _flush_serialized(self, post_fn: Callable, *, now: Optional[float] = None, limit: int = 50) -> Dict[str, Any]:
        """Deliver outside the data lock, then reconcile acknowledgements atomically."""
        current = time.time() if now is None else float(now)
        with self._locked():
            snapshot = self._read_records()
        if not snapshot:
            with self._locked():
                latest = self._read_records()
                if not latest:
                    self._write_status("online", 0)
                    return {"flushed": 0, "failed": 0, "remaining": 0, "deferred": 0}
                snapshot = latest

        selected = []
        deferred = 0
        for record in snapshot:
            if len(selected) >= max(1, int(limit)):
                deferred += 1
            elif float(record.get("next_attempt_at") or 0) > current:
                deferred += 1
            else:
                selected.append(record)

        outcomes = {}
        flushed = failed = 0
        for record in selected:
            record_id = str(record.get("id") or "")
            try:
                if "_corrupt_line" in record:
                    raise ValueError("corrupt queue record retained for operator inspection")
                try:
                    signature = inspect.signature(post_fn)
                    accepts_record_id = (
                        "record_id" in signature.parameters
                        or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values())
                    )
                except (TypeError, ValueError):
                    accepts_record_id = False
                if accepts_record_id:
                    ok, _response = post_fn(
                        record["path"], record["payload"], record_id=record_id
                    )
                else:
                    ok, _response = post_fn(record["path"], record["payload"])
                if not ok:
                    raise RuntimeError("delivery callback did not acknowledge the record")
                outcomes[record_id] = ("ack", None)
                flushed += 1
            except Exception as exc:
                outcomes[record_id] = ("retry", str(exc)[:500])
                failed += 1

        with self._locked():
            latest = self._read_records()
            reconciled = []
            for record in latest:
                outcome = outcomes.get(str(record.get("id") or ""))
                if outcome is None:
                    reconciled.append(record)
                    continue
                state, error = outcome
                if state == "ack":
                    continue
                attempts = int(record.get("attempts") or 0) + 1
                record["attempts"] = attempts
                record["last_error"] = error
                delay = min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * (2 ** min(attempts - 1, 10)))
                record["next_attempt_at"] = current + delay
                reconciled.append(record)
            self._atomic_write(reconciled)
            self._write_status(
                "online" if not reconciled else "degraded",
                len(reconciled),
                last_flush_at=current,
                last_flush_acknowledged=flushed,
            )
            return {
                "flushed": flushed,
                "failed": failed,
                "remaining": len(reconciled),
                "deferred": deferred,
            }

    def set_status(self, mode: str, queued: int = 0):
        self._write_status(mode, queued)

    def get_status(self) -> Dict[str, Any]:
        if not self.status_path.exists():
            return {"mode": "unknown", "queued": 0}
        try:
            value = json.loads(self.status_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {"mode": "unknown", "queued": 0}
        except (OSError, ValueError):
            return {"mode": "unknown", "queued": 0}
