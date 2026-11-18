"""Supervised outbox worker retry, migration, metrics and review-queue tests."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))

from outbox_worker import OutboxDispatcher  # noqa: E402
from transactional_outbox import SQLiteTransactionalOutbox  # noqa: E402


class FakeClock:
    def __init__(self, value=100.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


def make_store(tmp_path):
    store = SQLiteTransactionalOutbox(tmp_path / "gateway.sqlite3")
    result = store.execute_operation(
        tenant_id="tenant-a",
        idempotency_key="worker-test",
        request_hash="sha256:worker-test",
        handler=lambda _connection, operation_id: {"operation_id": operation_id},
        now=10,
    )
    return store, result


def test_schema_migration_preserves_legacy_pending_rows(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE cg_operations (
            operation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('completed', 'reconciliation_required')),
            result_json TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
            UNIQUE(tenant_id, idempotency_key)
        );
        CREATE TABLE cg_outbox (
            event_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL REFERENCES cg_operations(operation_id),
            tenant_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'inflight', 'delivered')),
            attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL,
            lease_owner TEXT, lease_until REAL, last_error TEXT,
            created_at REAL NOT NULL, delivered_at REAL,
            UNIQUE(operation_id, sequence)
        );
        CREATE INDEX idx_cg_outbox_ready ON cg_outbox(status, next_attempt_at, created_at);
        CREATE INDEX idx_cg_outbox_operation_order ON cg_outbox(operation_id, sequence, status);
        INSERT INTO cg_operations VALUES
            ('op-legacy', 'tenant-a', 'legacy-key', 'hash', 'completed', '{}', 1, 1);
        INSERT INTO cg_outbox VALUES
            ('event-legacy', 'op-legacy', 'tenant-a', 1, 'operation_intent',
             '{"tenant_id":"tenant-a"}', 'pending', 2, 1, NULL, NULL, NULL, 1, NULL);
    """)
    connection.commit()
    connection.close()

    store = SQLiteTransactionalOutbox(path)
    with store._connect() as migrated:
        schema = migrated.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='cg_outbox'"
        ).fetchone()["sql"]
        row = migrated.execute(
            "SELECT event_id, tenant_id, status, attempts FROM cg_outbox"
        ).fetchone()
    assert "review_required" in schema
    assert dict(row) == {
        "event_id": "event-legacy", "tenant_id": "tenant-a",
        "status": "pending", "attempts": 2,
    }
    assert store.outbox_counts()["pending"] == 1


def test_worker_uses_bounded_exponential_backoff_then_review_queue(tmp_path):
    store, _ = make_store(tmp_path)
    clock = FakeClock(100)
    calls = []

    def broken_sink(event_id, _payload):
        calls.append(event_id)
        raise OSError("ledger temporarily unavailable")

    worker = OutboxDispatcher(
        store, broken_sink, worker_id="worker-a", lease_seconds=10,
        max_attempts=2, base_backoff_seconds=2, max_backoff_seconds=5,
        clock=clock,
    )

    assert worker.dispatch_once() == "retry_scheduled"
    with store._connect() as connection:
        row = connection.execute(
            "SELECT attempts, next_attempt_at, status FROM cg_outbox WHERE event_id=?",
            (calls[0],),
        ).fetchone()
    assert tuple(row) == (1, 102.0, "pending")
    assert worker.dispatch_once() == "idle"

    clock.advance(2)
    assert worker.dispatch_once() == "review_required"
    review = store.review_queue()
    assert len(review) == 1
    assert review[0]["event_id"] == calls[0]
    assert review[0]["tenant_id"] == "tenant-a"
    assert review[0]["attempts"] == 2
    assert "ledger temporarily unavailable" in review[0]["last_error"]
    metrics = store.queue_metrics(now=clock())
    assert metrics["review_required"] == 1
    assert metrics["review_alert"] is True
    assert worker.health()["status"] == "review_required"


def test_worker_backoff_is_capped(tmp_path):
    store, _ = make_store(tmp_path)
    clock = FakeClock(50)
    worker = OutboxDispatcher(
        store, lambda *_: (_ for _ in ()).throw(OSError("offline")),
        worker_id="worker-cap", max_attempts=5,
        base_backoff_seconds=3, max_backoff_seconds=5, clock=clock,
    )
    expected = [3.0, 5.0]
    for delay in expected:
        assert worker.dispatch_once() == "retry_scheduled"
        with store._connect() as connection:
            row = connection.execute(
                "SELECT next_attempt_at FROM cg_outbox ORDER BY created_at, sequence LIMIT 1"
            ).fetchone()
        assert row["next_attempt_at"] == clock() + delay
        clock.advance(delay)


def test_queue_metrics_report_depth_age_retries_and_review_alert(tmp_path):
    store, _ = make_store(tmp_path)
    event = store.claim_next(worker_id="metrics-worker", now=20)
    store.retry_or_review(
        event_id=event["event_id"], worker_id="metrics-worker",
        error="temporary", max_attempts=4, delay_seconds=5, now=21,
    )
    metrics = store.queue_metrics(now=30)
    assert metrics["queue_depth"] == 2
    assert metrics["pending"] == 2
    assert metrics["oldest_pending_seconds"] == 20
    assert metrics["retry_count"] == 0
    assert metrics["review_required"] == 0
    assert metrics["review_alert"] is False


def test_worker_delivers_through_stable_id_audit_sink(tmp_path):
    from outbox_audit_sink import make_audit_ledger_sink
    import audit_ledger

    store, _ = make_store(tmp_path)
    ledger = tmp_path / "audit.jsonl"
    worker = OutboxDispatcher(
        store, make_audit_ledger_sink(ledger), worker_id="audit-worker",
        clock=FakeClock(200),
    )
    assert worker.dispatch_once() == "delivered"
    assert worker.dispatch_once() == "delivered"
    assert audit_ledger.verify_ledger(ledger)["records"] == 2
    assert store.outbox_counts()["delivered"] == 2


def test_review_queue_is_tenant_attributed_and_limit_is_bounded(tmp_path):
    store, result = make_store(tmp_path)
    event = store.claim_next(worker_id="review-worker", now=20)
    assert store.retry_or_review(
        event_id=event["event_id"], worker_id="review-worker",
        error="operator inspection required", max_attempts=1,
        delay_seconds=0, now=21,
    ) == "review_required"
    assert store.review_queue(limit=1)[0]["tenant_id"] == "tenant-a"
    with pytest.raises(ValueError):
        store.review_queue(limit=1001)
