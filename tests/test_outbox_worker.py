"""Supervised outbox worker retry, migration, metrics and review-queue tests."""
from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))

from outbox_worker import OutboxDispatcher, main as worker_main  # noqa: E402
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


def test_schema_migration_preserves_legacy_rows_and_metadata(tmp_path):
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
            ('event-pending', 'op-legacy', 'tenant-a', 1, 'operation_intent',
             '{"tenant_id":"tenant-a","legacy":true}', 'pending', 2, 11,
             NULL, NULL, 'temporary failure', 1, NULL),
            ('event-inflight', 'op-legacy', 'tenant-a', 2, 'operation_progress',
             '{"tenant_id":"tenant-a","lease":true}', 'inflight', 5, 12,
             'worker-old', 30, 'lease retained', 2, NULL),
            ('event-delivered', 'op-legacy', 'tenant-a', 3, 'operation_completed',
             '{"tenant_id":"tenant-a","done":true}', 'delivered', 1, 13,
             NULL, NULL, NULL, 3, 14);
    """)
    connection.commit()
    connection.close()

    store = SQLiteTransactionalOutbox(path)
    with store._connect() as migrated:
        schema = migrated.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='cg_outbox'"
        ).fetchone()["sql"]
        rows = migrated.execute(
            """SELECT event_id, tenant_id, sequence, status, attempts,
                      next_attempt_at, lease_owner, lease_until, last_error,
                      created_at, delivered_at
               FROM cg_outbox ORDER BY sequence"""
        ).fetchall()
        indexes = {
            row["name"] for row in migrated.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='cg_outbox'"
            )
        }
        foreign_keys = migrated.execute("PRAGMA foreign_key_list(cg_outbox)").fetchall()
        integrity = migrated.execute("PRAGMA integrity_check").fetchone()[0]

    assert "review_required" in schema
    assert [dict(row) for row in rows] == [
        {
            "event_id": "event-pending", "tenant_id": "tenant-a", "sequence": 1,
            "status": "pending", "attempts": 2, "next_attempt_at": 11.0,
            "lease_owner": None, "lease_until": None,
            "last_error": "temporary failure", "created_at": 1.0, "delivered_at": None,
        },
        {
            "event_id": "event-inflight", "tenant_id": "tenant-a", "sequence": 2,
            "status": "inflight", "attempts": 5, "next_attempt_at": 12.0,
            "lease_owner": "worker-old", "lease_until": 30.0,
            "last_error": "lease retained", "created_at": 2.0, "delivered_at": None,
        },
        {
            "event_id": "event-delivered", "tenant_id": "tenant-a", "sequence": 3,
            "status": "delivered", "attempts": 1, "next_attempt_at": 13.0,
            "lease_owner": None, "lease_until": None, "last_error": None,
            "created_at": 3.0, "delivered_at": 14.0,
        },
    ]
    assert {"idx_cg_outbox_ready", "idx_cg_outbox_operation_order"} <= indexes
    assert any(row["table"] == "cg_operations" for row in foreign_keys)
    assert integrity == "ok"
    assert store.outbox_counts() == {
        "pending": 1, "inflight": 1, "delivered": 1, "review_required": 0,
    }


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
    assert review[0]["last_error"] == "OSError: audit sink delivery failed"
    metrics = store.queue_metrics(now=clock())
    assert metrics["review_required"] == 1
    assert metrics["retry_count"] == 1
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


def test_sink_accept_then_lease_loss_replays_same_stable_event_id(tmp_path):
    from outbox_audit_sink import make_audit_ledger_sink
    import audit_ledger
    from transactional_outbox import OutboxLeaseLost

    store, _ = make_store(tmp_path)
    ledger = tmp_path / "replay-audit.jsonl"
    sink = make_audit_ledger_sink(ledger)
    clock = FakeClock(300)

    class LoseFirstAck:
        def __init__(self):
            self.calls = 0

        def acknowledge(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise OutboxLeaseLost("simulated worker lease loss after sink acceptance")
            return store.acknowledge(**kwargs)

    ack = LoseFirstAck()
    class StoreProxy:
        def __getattr__(self, name):
            return getattr(store, name)

        def acknowledge(self, **kwargs):
            return ack.acknowledge(**kwargs)

    first = OutboxDispatcher(
        StoreProxy(), sink, worker_id="worker-old", lease_seconds=5,
        clock=clock,
    )
    assert first.dispatch_once() == "lease_lost"
    assert audit_ledger.verify_ledger(ledger)["records"] == 1

    clock.advance(6)
    second = OutboxDispatcher(
        store, sink, worker_id="worker-recovered", lease_seconds=5,
        clock=clock,
    )
    assert second.dispatch_once() == "delivered"
    # Replay of the same stable ID was accepted as a duplicate, not appended.
    assert audit_ledger.verify_ledger(ledger)["records"] == 1
    assert store.outbox_counts()["delivered"] == 1


def test_heartbeat_is_atomic_private_and_stale_detection_fails_closed(tmp_path):
    from outbox_worker import _heartbeat_status, _write_heartbeat

    path = tmp_path / "worker.heartbeat"
    _write_heartbeat(
        path, {"worker_id": "worker-a", "status": "healthy"}, now=100
    )
    assert path.exists()
    assert path.stat().st_mode & 0o777 == 0o600
    age, stale, unhealthy = _heartbeat_status(path, now=150, stale_seconds=90)
    assert age == 50
    assert stale is False
    assert unhealthy is False

    age, stale, unhealthy = _heartbeat_status(path, now=191, stale_seconds=90)
    assert age == 91
    assert stale is True
    assert unhealthy is True

    _write_heartbeat(
        path, {"worker_id": "worker-a", "status": "degraded"}, now=150
    )
    age, stale, unhealthy = _heartbeat_status(path, now=151, stale_seconds=90)
    assert age == 1
    assert stale is False
    assert unhealthy is True

    _write_heartbeat(
        path, {"worker_id": "worker-a", "status": "review_required"}, now=150
    )
    age, stale, unhealthy = _heartbeat_status(path, now=151, stale_seconds=90)
    assert age == 1
    assert stale is False
    assert unhealthy is True

    path.write_text('{"timestamp": 150, "status": "healthy"}', encoding="utf-8")
    age, stale, unhealthy = _heartbeat_status(path, now=151, stale_seconds=90)
    assert age is None
    assert stale is True
    assert unhealthy is True

    missing_age, missing_stale, missing_unhealthy = _heartbeat_status(
        tmp_path / "missing.heartbeat", now=200, stale_seconds=90
    )
    assert missing_age is None
    assert missing_stale is True
    assert missing_unhealthy is True


def test_read_only_inspection_does_not_initialize_or_mutate_schema(tmp_path):
    path = tmp_path / "readonly.sqlite3"
    store = SQLiteTransactionalOutbox(path)
    before = sqlite3.connect(path)
    before_version = before.execute("PRAGMA schema_version").fetchone()[0]
    before.close()

    inspector = SQLiteTransactionalOutbox(
        path, initialize=False, read_only=True
    )
    assert inspector.queue_metrics(now=100)["queue_depth"] == 0
    assert inspector.review_queue() == []

    after = sqlite3.connect(path)
    after_version = after.execute("PRAGMA schema_version").fetchone()[0]
    after.close()
    assert after_version == before_version
    assert inspector.read_only is True


def test_health_once_cli_fails_closed_and_stays_read_only(tmp_path, capsys):
    from outbox_worker import _write_heartbeat

    database = tmp_path / "health.sqlite3"
    store = SQLiteTransactionalOutbox(database)
    heartbeat = tmp_path / "worker.heartbeat"
    arguments = [
        "--database", str(database),
        "--ledger", str(tmp_path / "audit.jsonl"),
        "--heartbeat-file", str(heartbeat),
        "--health-stale-seconds", "90",
        "--health-once",
    ]

    before = sqlite3.connect(database)
    before_version = before.execute("PRAGMA schema_version").fetchone()[0]
    before.close()

    _write_heartbeat(
        heartbeat, {"worker_id": "worker-a", "status": "healthy"}, now=time.time()
    )
    assert worker_main(arguments) == 0
    healthy_output = json.loads(capsys.readouterr().out)
    assert healthy_output["heartbeat_unhealthy"] is False
    assert healthy_output["status"] == "healthy"

    _write_heartbeat(
        heartbeat, {"worker_id": "worker-a", "status": "degraded"}, now=time.time()
    )
    assert worker_main(arguments) == 2
    degraded_output = json.loads(capsys.readouterr().out)
    assert degraded_output["heartbeat_unhealthy"] is True

    after = sqlite3.connect(database)
    after_version = after.execute("PRAGMA schema_version").fetchone()[0]
    after.close()
    assert after_version == before_version
    assert store.read_only is False
