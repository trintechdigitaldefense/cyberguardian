"""Append-only, hash-chained audit ledger for gateway audit events.

This is tamper-evident local evidence, not protection against an attacker who
can rewrite both the ledger and application binaries. Export checkpoints to an
independent protected system for stronger assurance.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class LedgerIntegrityError(RuntimeError):
    pass


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode("utf-8")


def _hash_record(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _verify_ledger_unlocked(path: Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {"valid": True, "records": 0, "head": GENESIS}
    previous = GENESIS
    count = 0
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.endswith("\n"):
                return {"valid": False, "records": count, "head": previous,
                        "error": f"truncated record at line {line_number}"}
            try:
                record = json.loads(line)
            except ValueError:
                return {"valid": False, "records": count, "head": previous,
                        "error": f"invalid JSON at line {line_number}"}
            if not isinstance(record, dict) or record.get("prev_hash") != previous:
                return {"valid": False, "records": count, "head": previous,
                        "error": f"chain link mismatch at line {line_number}"}
            actual = _hash_record(record)
            if not isinstance(record.get("hash"), str) or not __import__("hmac").compare_digest(actual, record["hash"]):
                return {"valid": False, "records": count, "head": previous,
                        "error": f"record hash mismatch at line {line_number}"}
            previous = actual
            count += 1
    return {"valid": True, "records": count, "head": previous}



def verify_ledger(path: Path) -> dict[str, Any]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        return _verify_ledger_unlocked(path)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def append_event(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        status = _verify_ledger_unlocked(path)
        if not status["valid"]:
            raise LedgerIntegrityError(status["error"])
        record = {
            "sequence": status["records"] + 1,
            "event_id": str(uuid.uuid4()),
            "recorded_at": time.time(),
            "prev_hash": status["head"],
            "event": event,
        }
        record["hash"] = _hash_record(record)
        encoded = _canonical(record) + b"\n"
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short append to audit ledger")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return record
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def export_verified_ledger(source: Path, destination: Path) -> dict[str, Any]:
    """Copy a verified, consistent ledger snapshot to a protected destination."""
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("audit export destination must differ from source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock_path = source.with_name(source.name + ".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        status = _verify_ledger_unlocked(source)
        if not status["valid"]:
            raise LedgerIntegrityError(status["error"])
        payload = source.read_bytes() if source.exists() else b""
        digest = hashlib.sha256(payload).hexdigest()
        fd, temp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp",
                                         dir=str(destination.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, destination)
            os.chmod(destination, 0o600)
            dir_fd = os.open(str(destination.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
        return {
            "source": str(source),
            "destination": str(destination),
            "records": status["records"],
            "head": status["head"],
            "sha256": digest,
            "bytes": len(payload),
        }
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
