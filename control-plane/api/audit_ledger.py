"""Append-only, hash-chained audit ledger for gateway audit events.

This is tamper-evident local evidence, not protection against an attacker who
can rewrite both the ledger and application binaries. Export checkpoints to an
independent protected system for stronger assurance.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
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


def _open_lock(path: Path, operation: int) -> int:
    path = Path(path)
    if path.is_symlink():
        raise PermissionError(f"audit lock must not be a symlink: {path}")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    fcntl.flock(fd, operation)
    return fd


def _reject_symlink(path: Path, label: str) -> None:
    if Path(path).is_symlink():
        raise PermissionError(f"{label} must not be a symlink: {path}")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode("utf-8")


def _hash_record(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _verify_ledger_unlocked(path: Path) -> dict[str, Any]:
    path = Path(path)
    _reject_symlink(path, "audit ledger")
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
    lock_fd = _open_lock(lock_path, fcntl.LOCK_SH)
    try:
        return _verify_ledger_unlocked(path)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def append_event(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    path = Path(path)
    _reject_symlink(path, "audit ledger")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = _open_lock(lock_path, fcntl.LOCK_EX)
    try:
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
    _reject_symlink(source, "audit source")
    _reject_symlink(destination, "audit destination")
    if source.resolve() == destination.resolve():
        raise ValueError("audit export destination must differ from source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock_path = source.with_name(source.name + ".lock")
    lock_fd = _open_lock(lock_path, fcntl.LOCK_SH)
    try:
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



def export_signed_checkpoint(source: Path, destination: Path, key: bytes) -> dict[str, Any]:
    """Export a verified snapshot plus an HMAC-authenticated manifest.

    Store the destination and checkpoint key independently from the live host.
    The HMAC proves possession of the checkpoint key; it is not a public-key
    signature and does not protect against compromise of that key.
    """
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("checkpoint signing key must contain at least 32 random bytes")
    manifest = export_verified_ledger(source, destination)
    signed = {
        "format": "cyberguardian-audit-checkpoint-v1",
        **manifest,
        "signed_at": time.time(),
        "algorithm": "HMAC-SHA256",
    }
    signature = hmac.new(key, _canonical(signed), hashlib.sha256).hexdigest()
    signed["signature"] = signature
    manifest_path = Path(str(destination) + ".manifest.json")
    _reject_symlink(manifest_path, "audit checkpoint manifest")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=manifest_path.name + ".", suffix=".tmp", dir=str(manifest_path.parent)
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(signed, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, manifest_path)
        os.chmod(manifest_path, 0o600)
        dir_fd = os.open(str(manifest_path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    return {**signed, "manifest_path": str(manifest_path)}


def verify_signed_checkpoint(snapshot: Path, key: bytes) -> dict[str, Any]:
    """Verify checkpoint HMAC, snapshot digest and audit-chain integrity."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("checkpoint signing key must contain at least 32 random bytes")
    snapshot = Path(snapshot)
    manifest_path = Path(str(snapshot) + ".manifest.json")
    _reject_symlink(snapshot, "audit checkpoint snapshot")
    _reject_symlink(manifest_path, "audit checkpoint manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("checkpoint manifest must be a JSON object")
    signature = manifest.pop("signature", None)
    if manifest.get("format") != "cyberguardian-audit-checkpoint-v1":
        raise ValueError("unsupported checkpoint manifest format")
    expected = hmac.new(key, _canonical(manifest), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise LedgerIntegrityError("checkpoint manifest signature mismatch")
    payload = snapshot.read_bytes()
    actual_digest = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual_digest, str(manifest.get("sha256") or "")):
        raise LedgerIntegrityError("checkpoint snapshot digest mismatch")
    chain = verify_ledger(snapshot)
    if not chain["valid"]:
        raise LedgerIntegrityError(chain["error"])
    if chain["records"] != int(manifest.get("records", -1)) or chain["head"] != manifest.get("head"):
        raise LedgerIntegrityError("checkpoint ledger head does not match signed manifest")
    return {
        "valid": True,
        "records": chain["records"],
        "head": chain["head"],
        "sha256": actual_digest,
        "manifest_path": str(manifest_path),
    }



def restore_signed_checkpoint(
    snapshot: Path, destination: Path, key: bytes, *, overwrite: bool = False
) -> dict[str, Any]:
    """Restore a verified checkpoint atomically to a separate ledger path."""
    snapshot = Path(snapshot)
    destination = Path(destination)
    if snapshot.resolve() == destination.resolve():
        raise ValueError("restore destination must differ from checkpoint snapshot")
    verified = verify_signed_checkpoint(snapshot, key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise FileExistsError("restore destination already exists; use explicit overwrite approval")
    payload = snapshot.read_bytes()
    fd, temp_name = tempfile.mkstemp(
        prefix=destination.name + ".", suffix=".restore.tmp", dir=str(destination.parent)
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temp_name, destination)
        else:
            # A hard-link install is atomic and fails if another process created
            # the destination after our preflight check.
            os.link(temp_name, destination)
            os.unlink(temp_name)
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
    restored = verify_ledger(destination)
    if not restored["valid"] or restored["head"] != verified["head"]:
        raise LedgerIntegrityError("restored ledger does not match verified checkpoint")
    return {
        "restored": True,
        "destination": str(destination),
        "records": restored["records"],
        "head": restored["head"],
        "sha256": verified["sha256"],
    }
