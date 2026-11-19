"""Failure-injection drills for transactional outbox and audit delivery."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))

from outbox_audit_sink import OutboxEventConflict, append_outbox_event_once, make_audit_ledger_sink  # noqa: E402
from transactional_outbox import OutboxLeaseLost, SQLiteTransactionalOutbox  # noqa: E402


def make_store(tmp_path):
    path = tmp_path / "cyberguardian.sqlite3"
    store = SQLiteTransactionalOutbox(path)
    result = store.execute_operation(
        tenant_id="tenant-a",
        idempotency_key="failure-drill",
        request_hash="sha256:failure-drill",
        handler=lambda _connection, operation_id: {
            "operation_id": operation_id,
            "asset_id": "asset-a",
        },
        now=10,
    )
    return path, store, result


def test_process_crash_before_commit_rolls_back_business_state_and_outbox(tmp_path):
    path = tmp_path / "crash-before-commit.sqlite3"
    store = SQLiteTransactionalOutbox(path)
    with store._connect() as connection:
        connection.execute(
            "CREATE TABLE business_state (asset_id TEXT PRIMARY KEY, state TEXT NOT NULL)"
        )

    script = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
from transactional_outbox import SQLiteTransactionalOutbox
store = SQLiteTransactionalOutbox(sys.argv[2])
def crash(connection, _operation_id):
    connection.execute(
        "INSERT INTO business_state(asset_id, state) VALUES ('asset-a', 'changed')"
    )
    os._exit(73)
store.execute_operation(
    tenant_id='tenant-a', idempotency_key='crash', request_hash='hash',
    handler=crash,
)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(API_DIR), str(path)],
        check=False,
    )
    assert result.returncode == 73

    with store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM business_state").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM cg_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM cg_outbox").fetchone()[0] == 0


def test_process_crash_after_ledger_fsync_replays_same_event_without_duplicate(tmp_path):
    path, store, _ = make_store(tmp_path)
    ledger = tmp_path / "audit.jsonl"
    script = r"""
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from outbox_audit_sink import make_audit_ledger_sink
from outbox_worker import OutboxDispatcher
from transactional_outbox import SQLiteTransactionalOutbox
store = SQLiteTransactionalOutbox(sys.argv[2])
sink = make_audit_ledger_sink(Path(sys.argv[3]))
def crash_after_sink(event_id, payload):
    sink(event_id, payload)
    os._exit(74)
worker = OutboxDispatcher(store, crash_after_sink, worker_id='crashed-worker',
                          lease_seconds=5)
worker.dispatch_once()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(API_DIR), str(path), str(ledger)],
        check=False,
    )
    assert result.returncode == 74

    import audit_ledger

    assert audit_ledger.verify_ledger(ledger)["records"] == 1
    recovery_time = time.time() + 6
    event = store.claim_next(
        worker_id="recovery-worker", lease_seconds=10, now=recovery_time
    )
    assert event is not None
    make_audit_ledger_sink(ledger)(event["event_id"], event["payload"])
    store.acknowledge(
        event_id=event["event_id"],
        worker_id="recovery-worker",
        now=recovery_time,
    )
    assert audit_ledger.verify_ledger(ledger)["records"] == 1
    assert store.outbox_counts()["delivered"] == 1


def test_expired_lease_is_reclaimed_and_old_worker_cannot_ack(tmp_path):
    _, store, _ = make_store(tmp_path)
    first = store.claim_next(worker_id="worker-old", lease_seconds=5, now=100)
    assert first is not None

    recovered_at = 106
    second = store.claim_next(
        worker_id="worker-new", lease_seconds=10, now=recovered_at
    )
    assert second is not None
    assert second["event_id"] == first["event_id"]
    assert second["lease_owner"] == "worker-new"

    with pytest.raises(OutboxLeaseLost):
        store.acknowledge(
            event_id=first["event_id"], worker_id="worker-old", now=recovered_at
        )
    store.acknowledge(
        event_id=second["event_id"], worker_id="worker-new", now=recovered_at
    )
    assert store.outbox_counts()["delivered"] == 1


def test_duplicate_stable_id_is_idempotent_but_conflicting_content_fails_closed(tmp_path):
    ledger = tmp_path / "duplicate.jsonl"
    event_id = "a" * 32
    original = {"tenant_id": "tenant-a", "phase": "completed"}
    first = append_outbox_event_once(
        ledger, event_id=event_id, event=original, recorded_at=10
    )
    replay = append_outbox_event_once(
        ledger, event_id=event_id, event=original, recorded_at=20
    )
    assert replay == first

    with pytest.raises(OutboxEventConflict):
        append_outbox_event_once(
            ledger, event_id=event_id,
            event={"tenant_id": "tenant-a", "phase": "different"},
            recorded_at=30,
        )

    import audit_ledger

    assert audit_ledger.verify_ledger(ledger)["records"] == 1


def test_corrupt_ledger_blocks_new_outbox_delivery(tmp_path):
    ledger = tmp_path / "corrupt.jsonl"
    append_outbox_event_once(
        ledger, event_id="b" * 32,
        event={"tenant_id": "tenant-a", "value": "original"},
    )
    original = ledger.read_text(encoding="utf-8")
    ledger.write_text(original.replace("original", "tampered"), encoding="utf-8")

    from audit_ledger import LedgerIntegrityError

    with pytest.raises(LedgerIntegrityError):
        append_outbox_event_once(
            ledger, event_id="c" * 32,
            event={"tenant_id": "tenant-a", "value": "new"},
        )
    assert "new" not in ledger.read_text(encoding="utf-8")


def test_reconciliation_state_is_tenant_scoped_ordered_and_not_repeated(tmp_path):
    _, store, operation = make_store(tmp_path)
    first = store.claim_next(worker_id="drill-worker", now=100)
    assert first is not None
    store.acknowledge(
        event_id=first["event_id"], worker_id="drill-worker", now=100
    )
    second = store.claim_next(worker_id="drill-worker", now=101)
    assert second is not None
    store.acknowledge(
        event_id=second["event_id"], worker_id="drill-worker", now=101
    )

    assert store.mark_reconciliation_required(
        tenant_id="tenant-a", operation_id=operation.operation_id,
        reason="agent response lost after local command commit", now=102,
    ) is True
    assert store.mark_reconciliation_required(
        tenant_id="tenant-a", operation_id=operation.operation_id,
        reason="duplicate reconciliation request", now=103,
    ) is False
    assert store.operation(
        tenant_id="tenant-a", operation_id=operation.operation_id
    )["status"] == "reconciliation_required"

    reconciliation = store.claim_next(worker_id="drill-worker", now=104)
    assert reconciliation is not None
    assert reconciliation["event_type"] == "operation_reconciliation_required"
    assert reconciliation["payload"]["tenant_id"] == "tenant-a"
    assert reconciliation["payload"]["phase"] == "reconciliation_required"
    assert store.claim_next(worker_id="other-worker", now=104) is None

    with pytest.raises(KeyError):
        store.mark_reconciliation_required(
            tenant_id="tenant-b", operation_id=operation.operation_id,
            reason="cross-tenant lookup must fail", now=105,
        )



def test_retry_waits_for_backoff_then_can_be_delivered(tmp_path):
    _, store, _ = make_store(tmp_path)
    event = store.claim_next(worker_id="retry-worker", now=100)
    assert event is not None
    assert store.retry_or_review(
        event_id=event["event_id"], worker_id="retry-worker",
        error="temporary sink outage", max_attempts=3,
        delay_seconds=5, now=100,
    ) == "retry_scheduled"
    assert store.claim_next(worker_id="retry-worker", now=104) is None

    retried = store.claim_next(worker_id="retry-worker", now=105)
    assert retried is not None
    assert retried["event_id"] == event["event_id"]
    assert retried["attempts"] == 2
    store.acknowledge(
        event_id=retried["event_id"], worker_id="retry-worker", now=105
    )
    assert store.outbox_counts()["delivered"] == 1
