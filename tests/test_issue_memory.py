from __future__ import annotations

import importlib.util
import multiprocessing
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))
import issue_memory


def _remember_worker(store_path: str, start: int):
    issue_memory.STORE = Path(store_path)
    for value in range(start, start + 10):
        issue_memory.remember_issue(
            title=f"unique issue {value}",
            asset_id=f"asset-{value}",
            tags=["test"],
        )


def test_issue_memory_writes_are_atomic_private_and_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(issue_memory, "STORE", tmp_path / "issues.jsonl")
    for value in range(issue_memory.MAX_ISSUES + 5):
        issue_memory.remember_issue(
            title=f"issue {value}", asset_id=f"asset-{value}", tags=["test"]
        )
    assert len(issue_memory.list_issues(limit=issue_memory.MAX_ISSUES)) == issue_memory.MAX_ISSUES
    assert issue_memory.STORE.stat().st_mode & 0o777 == 0o600
    assert issue_memory.STORE.with_name("issues.jsonl.lock").exists()


def test_duplicate_issue_updates_existing_record_without_duplicate(tmp_path, monkeypatch):
    monkeypatch.setattr(issue_memory, "STORE", tmp_path / "issues.jsonl")
    first = issue_memory.remember_issue("same", "asset-a", tags=["test"])
    second = issue_memory.remember_issue("same", "asset-a", tags=["test"], detection_id="det-2")
    assert first["id"] == second["id"]
    assert second["seen_count"] == 2
    assert second["last_detection_id"] == "det-2"
    assert len(issue_memory.list_issues()) == 1


def test_concurrent_issue_writers_do_not_lose_updates(tmp_path, monkeypatch):
    path = tmp_path / "issues.jsonl"
    monkeypatch.setattr(issue_memory, "STORE", path)
    workers = [
        multiprocessing.Process(target=_remember_worker, args=(str(path), i * 10))
        for i in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0
    assert len(issue_memory.list_issues(limit=100)) == 40


def test_update_issue_is_serialized_and_persists(tmp_path, monkeypatch):
    monkeypatch.setattr(issue_memory, "STORE", tmp_path / "issues.jsonl")
    item = issue_memory.remember_issue("review", "asset-a")
    updated = issue_memory.update_issue(item["id"], status="resolved", notes=["closed"])
    assert updated["status"] == "resolved"
    assert issue_memory.list_issues(status="resolved")[0]["id"] == item["id"]
