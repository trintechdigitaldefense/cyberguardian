from __future__ import annotations

import importlib.util
import json
import multiprocessing
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "control-plane" / "api" / "audit_ledger.py"
spec = importlib.util.spec_from_file_location("cg_audit_ledger_test", MODULE)
ledger = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ledger
spec.loader.exec_module(ledger)


def _append_worker(path: str, start: int):
    for value in range(start, start + 10):
        ledger.append_event(Path(path), {"event": "worker", "value": value})


def test_hash_chain_verifies_and_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    ledger.append_event(path, {"event": "login", "actor": "alice"})
    ledger.append_event(path, {"event": "approval", "actor": "alice"})
    result = ledger.verify_ledger(path)
    assert result["valid"] is True
    assert result["records"] == 2

    records = path.read_text().splitlines()
    record = json.loads(records[0])
    record["event"]["actor"] = "mallory"
    records[0] = json.dumps(record)
    path.write_text("\n".join(records) + "\n")
    result = ledger.verify_ledger(path)
    assert result["valid"] is False
    assert "hash mismatch" in result["error"]


def test_ledger_append_refuses_to_extend_corrupted_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"broken":true}\n')
    try:
        ledger.append_event(path, {"event": "should-not-append"})
    except ledger.LedgerIntegrityError:
        pass
    else:
        raise AssertionError("corrupt audit chain must not be extended")


def test_concurrent_audit_writers_preserve_sequence_and_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    workers = [
        multiprocessing.Process(target=_append_worker, args=(str(path), i * 10))
        for i in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0
    result = ledger.verify_ledger(path)
    assert result["valid"] is True
    assert result["records"] == 40
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [item["sequence"] for item in records] == list(range(1, 41))
    assert path.stat().st_mode & 0o777 == 0o600



def test_export_creates_verified_consistent_snapshot(tmp_path):
    source = tmp_path / "audit.jsonl"
    destination = tmp_path / "exports" / "audit-snapshot.jsonl"
    ledger.append_event(source, {"event": "export-test", "tenant": "client-a"})
    manifest = ledger.export_verified_ledger(source, destination)
    assert manifest["records"] == 1
    assert manifest["sha256"]
    assert destination.read_bytes() == source.read_bytes()
    assert ledger.verify_ledger(destination)["valid"] is True
    assert destination.stat().st_mode & 0o777 == 0o600


def test_export_refuses_corrupt_source(tmp_path):
    source = tmp_path / "audit.jsonl"
    source.write_text('{"bad":true}\n')
    try:
        ledger.export_verified_ledger(source, tmp_path / "export.jsonl")
    except ledger.LedgerIntegrityError:
        pass
    else:
        raise AssertionError("corrupt audit source must not be exported")



def test_signed_checkpoint_verifies_and_rejects_wrong_key_or_tampering(tmp_path):
    source = tmp_path / "live-audit.jsonl"
    snapshot = tmp_path / "backup" / "audit.jsonl"
    key = b"k" * 32
    ledger.append_event(source, {"event": "operator-action", "actor": "operator-a"})
    ledger.export_signed_checkpoint(source, snapshot, key)
    verified = ledger.verify_signed_checkpoint(snapshot, key)
    assert verified["valid"] is True
    assert verified["records"] == 1

    try:
        ledger.verify_signed_checkpoint(snapshot, b"x" * 32)
    except ledger.LedgerIntegrityError:
        pass
    else:
        raise AssertionError("wrong checkpoint key must be rejected")

    snapshot.write_bytes(snapshot.read_bytes() + b'{"tampered":true}\\n')
    try:
        ledger.verify_signed_checkpoint(snapshot, key)
    except ledger.LedgerIntegrityError:
        pass
    else:
        raise AssertionError("modified checkpoint snapshot must be rejected")


def test_signed_checkpoint_requires_strong_key(tmp_path):
    source = tmp_path / "live-audit.jsonl"
    ledger.append_event(source, {"event": "test"})
    try:
        ledger.export_signed_checkpoint(source, tmp_path / "backup.jsonl", b"short")
    except ValueError as exc:
        assert "32 random bytes" in str(exc)
    else:
        raise AssertionError("weak checkpoint key must be rejected")



def test_restore_signed_checkpoint_is_atomic_and_requires_explicit_overwrite(tmp_path):
    source = tmp_path / "source.jsonl"
    snapshot = tmp_path / "backup" / "audit.jsonl"
    restored = tmp_path / "clean-instance" / "audit.jsonl"
    key = b"r" * 32
    ledger.append_event(source, {"event": "restore-test", "tenant": "tenant-a"})
    ledger.export_signed_checkpoint(source, snapshot, key)

    result = ledger.restore_signed_checkpoint(snapshot, restored, key)
    assert result["restored"] is True
    assert restored.read_bytes() == snapshot.read_bytes()
    assert ledger.verify_ledger(restored)["valid"] is True
    assert restored.stat().st_mode & 0o777 == 0o600

    try:
        ledger.restore_signed_checkpoint(snapshot, restored, key)
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing restore destination must be protected")

    replacement = ledger.restore_signed_checkpoint(snapshot, restored, key, overwrite=True)
    assert replacement["head"] == result["head"]



def test_audit_ledger_handles_short_writes_without_corrupting_chain(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    original_write = ledger.os.write
    calls = {"count": 0}

    def short_write(fd, data):
        if calls["count"] == 0:
            calls["count"] += 1
            return original_write(fd, data[:7])
        return original_write(fd, data)

    monkeypatch.setattr(ledger.os, "write", short_write)
    ledger.append_event(path, {"action": "short-write-test"})
    assert ledger.verify_ledger(path)["valid"] is True


def test_audit_ledger_partial_write_fails_closed_on_next_append(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    original_write = ledger.os.write
    calls = {"count": 0}

    def partial_then_fail(fd, data):
        if calls["count"] == 0:
            calls["count"] += 1
            return original_write(fd, data[:9])
        raise OSError("simulated crash during audit append")

    monkeypatch.setattr(ledger.os, "write", partial_then_fail)
    try:
        ledger.append_event(path, {"action": "partial-write"})
    except OSError as exc:
        assert "simulated crash" in str(exc)
    else:
        raise AssertionError("partial write fault must propagate")

    monkeypatch.setattr(ledger.os, "write", original_write)
    assert ledger.verify_ledger(path)["valid"] is False
    try:
        ledger.append_event(path, {"action": "must-not-append-after-corruption"})
    except ledger.LedgerIntegrityError:
        pass
    else:
        raise AssertionError("append must fail closed after a partial ledger record")
