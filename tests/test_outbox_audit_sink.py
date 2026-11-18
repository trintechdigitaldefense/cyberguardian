from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))

import audit_ledger  # noqa: E402
from outbox_audit_sink import (  # noqa: E402
    OutboxEventConflict,
    append_outbox_event_once,
    make_audit_ledger_sink,
)


def test_outbox_sink_uses_stable_id_and_replays_after_acknowledgement_crash(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    event_id = "a" * 32
    event = {"fields": {"event": "operation_completed", "tenant_id": "tenant-a"}}

    first = append_outbox_event_once(
        ledger, event_id=event_id, event=event, recorded_at=100,
    )
    # Models: ledger fsync succeeded, but the outbox worker died before ack.
    replay = append_outbox_event_once(
        ledger, event_id=event_id, event=event, recorded_at=200,
    )

    assert first == replay
    assert replay["event_id"] == event_id
    assert audit_ledger.verify_ledger(ledger)["records"] == 1


def test_outbox_sink_rejects_same_id_with_different_content(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    append_outbox_event_once(
        ledger, event_id="b" * 32, event={"fields": {"value": 1}},
    )

    with pytest.raises(OutboxEventConflict):
        append_outbox_event_once(
            ledger, event_id="b" * 32, event={"fields": {"value": 2}},
        )

    assert audit_ledger.verify_ledger(ledger)["records"] == 1


def test_outbox_sink_fails_closed_on_corrupt_existing_chain(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    audit_ledger.append_event(ledger, {"fields": {"event": "original"}})
    ledger.write_text('{"not":"a valid chain"}\\n', encoding="utf-8")

    with pytest.raises(audit_ledger.LedgerIntegrityError):
        append_outbox_event_once(
            ledger, event_id="c" * 32, event={"fields": {"event": "new"}},
        )


def test_concurrent_duplicate_outbox_delivery_appends_one_record(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    event_id = "d" * 32
    event = {"fields": {"event": "operation_intent", "tenant_id": "tenant-a"}}
    barrier = threading.Barrier(6)
    results = []
    errors = []

    def deliver():
        try:
            barrier.wait(timeout=5)
            results.append(append_outbox_event_once(
                ledger, event_id=event_id, event=event,
            ))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=deliver) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 6
    assert len({result["hash"] for result in results}) == 1
    assert audit_ledger.verify_ledger(ledger)["records"] == 1


def test_factory_sink_matches_transactional_outbox_callback_contract(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    sink = make_audit_ledger_sink(ledger)
    sink("e" * 32, {"operation_id": "op-1", "phase": "accepted"})

    records = [
        __import__("json").loads(line)
        for line in ledger.read_text(encoding="utf-8").splitlines()
    ]
    assert records[0]["event_id"] == "e" * 32
    assert records[0]["event"]["source"] == "cyberguardian_transactional_outbox"
    assert records[0]["event"]["fields"]["operation_id"] == "op-1"
