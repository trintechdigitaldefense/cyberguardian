from __future__ import annotations

import importlib.util
import json
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
    monkeypatch.setattr(issue_memory, "MAX_ISSUES", 10)
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



def test_corrupt_issue_memory_fails_closed_without_rewriting(tmp_path, monkeypatch):
    path = tmp_path / "issues.jsonl"
    path.write_text("{broken-json}\n")
    monkeypatch.setattr(issue_memory, "STORE", path)
    try:
        issue_memory.remember_issue("new", "asset-new")
    except issue_memory.IssueMemoryIntegrityError:
        pass
    else:
        raise AssertionError("corrupt issue memory must block read-modify-write")
    assert path.read_text() == "{broken-json}\n"



def test_issue_capacity_archives_evicted_records_without_data_loss(tmp_path, monkeypatch):
    path = tmp_path / "issues.jsonl"
    monkeypatch.setattr(issue_memory, "STORE", path)
    monkeypatch.setattr(issue_memory, "MAX_ISSUES", 3)
    monkeypatch.setattr(issue_memory, "MAX_ARCHIVED_ISSUES", 10)
    created = []
    for value in range(5):
        created.append(
            issue_memory.remember_issue(
                title=f"archive issue {value}",
                asset_id=f"asset-{value}",
                tags=["archive-test"],
            )
        )
    active = issue_memory.list_issues(limit=10)
    archived = issue_memory.list_archived_issues(limit=10)
    assert len(active) == 3
    assert len(archived) == 2
    assert {item["id"] for item in active + archived} == {item["id"] for item in created}
    archive_path = path.with_name("issues_archive.jsonl")
    assert archive_path.stat().st_mode & 0o777 == 0o600


def test_issue_archive_capacity_fails_closed_without_dropping_active_records(tmp_path, monkeypatch):
    path = tmp_path / "issues.jsonl"
    monkeypatch.setattr(issue_memory, "STORE", path)
    monkeypatch.setattr(issue_memory, "MAX_ISSUES", 1)
    monkeypatch.setattr(issue_memory, "MAX_ARCHIVED_ISSUES", 1)
    issue_memory.remember_issue("first", "asset-1")
    issue_memory.remember_issue("second", "asset-2")
    try:
        issue_memory.remember_issue("third", "asset-3")
    except issue_memory.IssueMemoryCapacityError:
        pass
    else:
        raise AssertionError("full issue archive must reject new records")
    assert [item["title"] for item in issue_memory.list_issues()] == ["second"]
    assert [item["title"] for item in issue_memory.list_archived_issues()] == ["first"]



def test_issue_memory_records_are_tenant_isolated_and_updates_are_object_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(issue_memory, "STORE", tmp_path / "issues.jsonl")
    tenant_a = issue_memory.remember_issue(
        "same finding", "asset-shared", tags=["malware"], tenant_id="tenant-a"
    )
    tenant_b = issue_memory.remember_issue(
        "same finding", "asset-shared", tags=["malware"], tenant_id="tenant-b"
    )
    assert tenant_a["id"] != tenant_b["id"]
    assert tenant_a["tenant_id"] == "tenant-a"
    assert tenant_b["tenant_id"] == "tenant-b"

    assert [item["id"] for item in issue_memory.list_issues(tenant_id="tenant-a")] == [tenant_a["id"]]
    assert [item["id"] for item in issue_memory.list_issues(tenant_id="tenant-b")] == [tenant_b["id"]]
    assert issue_memory.update_issue(
        tenant_b["id"], tenant_id="tenant-a", status="resolved"
    ) is None
    updated = issue_memory.update_issue(
        tenant_b["id"], tenant_id="tenant-b", status="resolved"
    )
    assert updated and updated["status"] == "resolved"
    assert updated["tenant_id"] == "tenant-b"


def test_issue_memory_uses_verified_tenant_context_for_reads_and_updates(tmp_path, monkeypatch):
    monkeypatch.setattr(issue_memory, "STORE", tmp_path / "issues.jsonl")
    a = issue_memory.remember_issue("issue A", "asset-a", tenant_id="tenant-a")
    b = issue_memory.remember_issue("issue B", "asset-b", tenant_id="tenant-b")
    token = issue_memory.set_current_tenant("tenant-a")
    try:
        assert [item["id"] for item in issue_memory.list_issues()] == [a["id"]]
        assert issue_memory.update_issue(b["id"], status="resolved") is None
        updated = issue_memory.update_issue(a["id"], status="watching")
        assert updated and updated["status"] == "watching"
    finally:
        issue_memory.reset_current_tenant(token)


def test_production_issue_memory_fails_closed_without_tenant_context(tmp_path, monkeypatch):
    monkeypatch.setattr(issue_memory, "STORE", tmp_path / "issues.jsonl")
    monkeypatch.setenv("CG_PRODUCTION", "1")
    item = issue_memory.remember_issue("tenant issue", "asset-a", tenant_id="tenant-a")
    assert issue_memory.list_issues() == []
    assert issue_memory.update_issue(item["id"], status="resolved") is None
    try:
        issue_memory.remember_issue("missing tenant", "asset-b")
    except PermissionError as exc:
        assert "tenant context is required" in str(exc)
    else:
        raise AssertionError("production issue creation must require verified tenant context")


def test_valid_json_with_invalid_issue_schema_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "issues.jsonl"
    path.write_text('null\n', encoding="utf-8")
    monkeypatch.setattr(issue_memory, "STORE", path)
    try:
        issue_memory.list_issues()
    except issue_memory.IssueMemoryIntegrityError:
        pass
    else:
        raise AssertionError("invalid issue schema must not be silently discarded")



def test_legacy_issue_tenant_migration_updates_active_and_archive_atomically(tmp_path, monkeypatch):
    store = tmp_path / "issues.jsonl"
    archive = tmp_path / "issues-archive.jsonl"
    monkeypatch.setattr(issue_memory, "STORE", store)
    monkeypatch.setattr(issue_memory, "ARCHIVE", archive)
    monkeypatch.setattr(issue_memory, "MAX_ISSUES", 1)

    active = issue_memory.remember_issue("active finding", "asset-b", tenant_id="tenant-b")
    archived = issue_memory.remember_issue("archived finding", "asset-a", tenant_id="tenant-a")

    active_rows = [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines()]
    archive_rows = [json.loads(line) for line in archive.read_text(encoding="utf-8").splitlines()]
    for row in active_rows + archive_rows:
        row.pop("tenant_id", None)
    store.write_text("".join(json.dumps(row) + "\n" for row in active_rows), encoding="utf-8")
    archive.write_text("".join(json.dumps(row) + "\n" for row in archive_rows), encoding="utf-8")

    mapping = {"asset-a": "tenant-a", "asset-b": "tenant-b"}
    result = issue_memory.migrate_legacy_tenant_ids(mapping.get)
    assert result["active_migrated"] == 1
    assert result["archived_migrated"] == 1
    assert result["unresolved"] == []
    # The first-created tenant-b issue was evicted to the archive; the
    # second tenant-a issue remains active after the bounded-store rotation.
    assert issue_memory.list_issues(tenant_id="tenant-a")[0]["id"] == archived["id"]
    assert issue_memory.list_archived_issues(tenant_id="tenant-b")[0]["id"] == active["id"]



def test_issue_memory_rejects_symlinked_store_and_lock_paths(tmp_path, monkeypatch):
    target = tmp_path / "target.jsonl"
    target.write_text("", encoding="utf-8")
    linked_store = tmp_path / "issues.jsonl"
    linked_store.symlink_to(target)
    monkeypatch.setattr(issue_memory, "STORE", linked_store)
    try:
        issue_memory.remember_issue("must-not-write", "asset-a")
    except PermissionError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlinked issue-memory store must be rejected")
    assert target.read_text(encoding="utf-8") == ""

    store = tmp_path / "safe-issues.jsonl"
    lock_target = tmp_path / "lock-target"
    lock_target.write_text("untouched", encoding="utf-8")
    (tmp_path / "safe-issues.jsonl.lock").symlink_to(lock_target)
    monkeypatch.setattr(issue_memory, "STORE", store)
    try:
        issue_memory.remember_issue("must-not-lock", "asset-a")
    except PermissionError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlinked issue-memory lock must be rejected")
    assert lock_target.read_text(encoding="utf-8") == "untouched"
