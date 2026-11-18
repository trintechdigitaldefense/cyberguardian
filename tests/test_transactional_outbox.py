"""Failure, replay, concurrency and recovery tests for the R4 outbox."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane" / "api"))
from transactional_outbox import (  # noqa: E402
    IdempotencyConflict,
    OutboxLeaseLost,
    SQLiteTransactionalOutbox,
)


def make_store(tmp_path):
    store = SQLiteTransactionalOutbox(tmp_path / "gateway.sqlite3")
    with store._connect() as connection:
        connection.execute(
            "CREATE TABLE business_state (name TEXT PRIMARY KEY, value INTEGER NOT NULL)"
        )
    return store


def handler(connection, _operation_id):
    connection.execute(
        "INSERT INTO business_state(name, value) VALUES ('changed', 1)"
    )
    return {"accepted": True}


def test_business_state_operation_and_outbox_commit_together(tmp_path):
    store = make_store(tmp_path)
    result = store.execute_operation(
        tenant_id="tenant-a", idempotency_key="request-1",
        request_hash="sha256:abc", handler=handler, now=100,
    )
    assert result.status == "completed"
    assert result.replayed is False
    assert store.operation(tenant_id="tenant-a", operation_id=result.operation_id)["result"] == {"accepted": True}
    assert store.outbox_counts() == {"pending": 2, "inflight": 0, "delivered": 0}
    with store._connect() as connection:
        assert connection.execute("SELECT value FROM business_state WHERE name='changed'").fetchone()[0] == 1
        events = connection.execute(
            "SELECT event_type FROM cg_outbox WHERE operation_id=? ORDER BY sequence",
            (result.operation_id,),
        ).fetchall()
        assert [row["event_type"] for row in events] == [
            "operation_intent", "operation_completed"
        ]


def test_crash_during_handler_rolls_back_state_intent_and_completion(tmp_path):
    store = make_store(tmp_path)

    def crash(connection, _operation_id):
        connection.execute("INSERT INTO business_state VALUES ('partial', 1)")
        raise RuntimeError("simulated process failure before commit")

    with pytest.raises(RuntimeError, match="simulated"):
        store.execute_operation(
            tenant_id="tenant-a", idempotency_key="request-crash",
            request_hash="sha256:crash", handler=crash,
        )
    with store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM business_state").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM cg_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM cg_outbox").fetchone()[0] == 0


def test_same_key_replays_original_result_without_repeating_business_write(tmp_path):
    store = make_store(tmp_path)
    first = store.execute_operation(
        tenant_id="tenant-a", idempotency_key="stable-key",
        request_hash="sha256:one", handler=handler,
    )
    second = store.execute_operation(
        tenant_id="tenant-a", idempotency_key="stable-key",
        request_hash="sha256:one", handler=handler,
    )
    assert second.replayed is True
    assert second.operation_id == first.operation_id
    assert second.result == first.result
    with store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM business_state").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM cg_operations").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM cg_outbox").fetchone()[0] == 2


def test_reusing_key_for_different_request_is_rejected(tmp_path):
    store = make_store(tmp_path)
    store.execute_operation(
        tenant_id="tenant-a", idempotency_key="stable-key",
        request_hash="sha256:one", handler=handler,
    )
    with pytest.raises(IdempotencyConflict):
        store.execute_operation(
            tenant_id="tenant-a", idempotency_key="stable-key",
            request_hash="sha256:two", handler=handler,
        )


def test_idempotency_scope_is_tenant_specific(tmp_path):
    store = make_store(tmp_path)
    def tenant_handler(connection, operation_id):
        connection.execute(
            "INSERT INTO business_state(name, value) VALUES (?, 1)", (operation_id,)
        )
        return {"operation_id": operation_id}

    first = store.execute_operation(
        tenant_id="tenant-a", idempotency_key="same-key",
        request_hash="sha256:one", handler=tenant_handler,
    )
    second = store.execute_operation(
        tenant_id="tenant-b", idempotency_key="same-key",
        request_hash="sha256:one", handler=tenant_handler,
    )
    assert first.operation_id != second.operation_id
    assert store.operation(tenant_id="tenant-a", operation_id=second.operation_id) is None
    assert store.operation(tenant_id="tenant-b", operation_id=second.operation_id) is not None


def test_concurrent_duplicate_requests_execute_business_handler_once(tmp_path):
    store = make_store(tmp_path)
    barrier = threading.Barrier(8)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(store.execute_operation(
                tenant_id="tenant-a", idempotency_key="concurrent-key",
                request_hash="sha256:same", handler=handler,
            ))
        except BaseException as exc:  # retain thread failures for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 8
    assert len({item.operation_id for item in results}) == 1
    assert sum(not item.replayed for item in results) == 1
    with store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM business_state").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM cg_outbox").fetchone()[0] == 2


def test_crash_after_delivery_before_ack_retries_same_event_id(tmp_path):
    store = make_store(tmp_path)
    store.execute_operation(
        tenant_id="tenant-a", idempotency_key="delivery-key",
        request_hash="sha256:delivery", handler=handler, now=10,
    )
    accepted_ids = set()
    receiver_effects = []

    def idempotent_receiver(event_id, payload):
        if event_id not in accepted_ids:
            accepted_ids.add(event_id)
            receiver_effects.append(payload)

    first_claim = store.claim_next(worker_id="worker-1", lease_seconds=5, now=20)
    assert first_claim["event_type"] == "operation_intent"
    idempotent_receiver(first_claim["event_id"], first_claim["payload"])
    # Simulated process death: receiver accepted the event, sender did not ack.
    assert store.claim_next(worker_id="worker-2", lease_seconds=5, now=24) is None
    retry_claim = store.claim_next(worker_id="worker-2", lease_seconds=5, now=26)
    assert retry_claim["event_id"] == first_claim["event_id"]
    assert retry_claim["attempts"] == 2
    idempotent_receiver(retry_claim["event_id"], retry_claim["payload"])
    store.acknowledge(
        event_id=retry_claim["event_id"], worker_id="worker-2", now=27,
    )
    assert len(receiver_effects) == 1
    assert store.outbox_counts()["delivered"] == 1


def test_outbox_preserves_per_operation_event_order(tmp_path):
    store = make_store(tmp_path)
    result = store.execute_operation(
        tenant_id="tenant-a", idempotency_key="ordered-key",
        request_hash="sha256:ordered", handler=handler, now=1,
    )
    first = store.claim_next(worker_id="worker-a", now=2)
    assert first["event_type"] == "operation_intent"
    # Completion cannot pass an intent that is leased but not acknowledged.
    assert store.claim_next(worker_id="worker-b", now=3) is None
    store.acknowledge(event_id=first["event_id"], worker_id="worker-a", now=4)
    second = store.claim_next(worker_id="worker-b", now=5)
    assert second["event_type"] == "operation_completed"
    assert second["payload"]["operation_id"] == result.operation_id


def test_wrong_worker_cannot_acknowledge_another_workers_lease(tmp_path):
    store = make_store(tmp_path)
    store.execute_operation(
        tenant_id="tenant-a", idempotency_key="lease-key",
        request_hash="sha256:lease", handler=handler,
    )
    event = store.claim_next(worker_id="owner")
    with pytest.raises(OutboxLeaseLost):
        store.acknowledge(event_id=event["event_id"], worker_id="intruder")


def test_failed_delivery_is_retried_after_backoff(tmp_path):
    store = make_store(tmp_path)
    store.execute_operation(
        tenant_id="tenant-a", idempotency_key="retry-key",
        request_hash="sha256:retry", handler=handler, now=1,
    )
    calls = []

    def failing_sink(event_id, _payload):
        calls.append(event_id)
        raise OSError("audit endpoint unavailable")

    assert store.dispatch_once(
        worker_id="worker", sink=failing_sink, retry_delay=10, now=2,
    )
    assert store.claim_next(worker_id="other", now=11) is None
    retry = store.claim_next(worker_id="other", now=12)
    assert retry["event_id"] == calls[0]
    assert retry["attempts"] == 2


def test_expired_worker_lease_cannot_acknowledge(tmp_path):
    store = make_store(tmp_path)
    store.execute_operation(
        tenant_id="tenant-a", idempotency_key="expired-lease",
        request_hash="sha256:expired", handler=handler, now=1,
    )
    event = store.claim_next(worker_id="stale-worker", lease_seconds=2, now=2)
    with pytest.raises(OutboxLeaseLost):
        store.acknowledge(event_id=event["event_id"], worker_id="stale-worker", now=5)
    reclaimed = store.claim_next(worker_id="new-worker", lease_seconds=5, now=5)
    assert reclaimed["event_id"] == event["event_id"]
    store.acknowledge(event_id=reclaimed["event_id"], worker_id="new-worker", now=6)


def test_hard_process_exit_recovers_uncommitted_transaction(tmp_path):
    import subprocess

    store = make_store(tmp_path)
    script = r"""
import os
import sys
from transactional_outbox import SQLiteTransactionalOutbox
store = SQLiteTransactionalOutbox(sys.argv[1])
def die(connection, operation_id):
    connection.execute("INSERT INTO business_state(name, value) VALUES ('killed', 1)")
    os._exit(73)
store.execute_operation(
    tenant_id="tenant-a", idempotency_key="hard-crash",
    request_hash="sha256:hard-crash", handler=die,
)
"""
    env = dict(__import__("os").environ)
    module_dir = str(Path(__file__).resolve().parents[1] / "control-plane" / "api")
    env["PYTHONPATH"] = module_dir + __import__("os").pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", script, str(store.database_path)],
        env=env, check=False, timeout=10,
    )
    assert result.returncode == 73
    with store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM business_state").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM cg_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM cg_outbox").fetchone()[0] == 0


def test_concurrent_workers_cannot_claim_same_or_later_event(tmp_path):
    store = make_store(tmp_path)
    store.execute_operation(
        tenant_id="tenant-a", idempotency_key="worker-race",
        request_hash="sha256:worker-race", handler=handler, now=1,
    )
    barrier = threading.Barrier(2)
    claims = []
    errors = []

    def worker(worker_id):
        try:
            barrier.wait(timeout=5)
            claims.append(store.claim_next(worker_id=worker_id, now=2))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"worker-{i}",)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert sum(claim is not None for claim in claims) == 1
    assert len({claim["event_id"] for claim in claims if claim is not None}) == 1
