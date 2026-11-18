"""Stable-ID, duplicate-aware delivery from the SQLite outbox to the audit ledger.

The ledger remains the durable sink. A record's event_id is the outbox event ID,
so a crash after fsync but before the SQLite acknowledgement can safely replay.
"""
from __future__ import annotations

import fcntl
import os
import re
import time
from pathlib import Path
from typing import Any

import audit_ledger


class OutboxEventConflict(RuntimeError):
    """A stable outbox event ID was reused with different event content."""


_EVENT_ID = re.compile(r"^[0-9a-f]{32}$")


def append_outbox_event_once(
    ledger_path: str | Path,
    *,
    event_id: str,
    event: dict[str, Any],
    recorded_at: float | None = None,
) -> dict[str, Any]:
    """Append one outbox event exactly once to the hash-chained ledger.

    The operation is serialized under the ledger's exclusive lock. The full
    existing chain is verified before either accepting a duplicate or
    appending. Duplicate IDs with different content fail closed.
    """
    stable_id = str(event_id).strip().lower()
    if not _EVENT_ID.fullmatch(stable_id):
        raise ValueError("outbox event ID must be 32 lowercase hexadecimal characters")
    if not isinstance(event, dict):
        raise TypeError("outbox event must be an object")

    path = Path(ledger_path)
    audit_ledger._reject_symlink(path, "audit ledger")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = audit_ledger._open_lock(
        path.with_name(path.name + ".lock"), fcntl.LOCK_EX
    )
    try:
        matches: list[dict[str, Any]] = []

        def find_existing(record: dict[str, Any]) -> None:
            if record.get("event_id") == stable_id:
                matches.append(record)

        integrity = audit_ledger._verify_ledger_unlocked(
            path, on_record=find_existing
        )
        if not integrity.get("valid"):
            raise audit_ledger.LedgerIntegrityError(
                str(integrity.get("error") or "audit ledger integrity failure")
            )

        if matches:
            if len(matches) != 1 or matches[0].get("event") != event:
                raise OutboxEventConflict(
                    "outbox event ID already exists with different ledger content"
                )
            return matches[0]

        timestamp = time.time() if recorded_at is None else float(recorded_at)
        record = {
            "sequence": int(integrity["records"]) + 1,
            "event_id": stable_id,
            "recorded_at": timestamp,
            "prev_hash": str(integrity["head"]),
            "event": event,
        }
        record["hash"] = audit_ledger._hash_record(record)
        encoded = audit_ledger._canonical(record) + b"\n"
        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags, 0o600)
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


def make_audit_ledger_sink(ledger_path: str | Path):
    """Return a sink callback compatible with SQLiteTransactionalOutbox."""
    path = Path(ledger_path)

    def sink(event_id: str, payload: dict[str, Any]) -> None:
        append_outbox_event_once(
            path,
            event_id=event_id,
            event={"source": "cyberguardian_transactional_outbox", "fields": payload},
        )

    return sink
