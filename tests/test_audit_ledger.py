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
