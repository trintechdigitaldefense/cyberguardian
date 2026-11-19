"""Tests proving live gateway mutations share the outbox SQLite transaction."""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane" / "api"))
from transactional_outbox import SQLiteTransactionalOutbox  # noqa: E402


def setup_database(tmp_path):
    path = tmp_path / "gateway.sqlite3"
    outbox = SQLiteTransactionalOutbox(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE agent_commands (id TEXT PRIMARY KEY, status TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO agent_commands VALUES ('cmd-1', 'queued')")
    return path, outbox


def test_live_operation_commits_business_state_and_outbox_on_same_connection(tmp_path):
    path, outbox = setup_database(tmp_path)
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        def deliver(conn, operation_id):
            cursor = conn.execute(
                "UPDATE agent_commands SET status='delivered' "
                "WHERE id='cmd-1' AND status='queued'"
            )
            assert cursor.rowcount == 1
            return {
                "tenant_id": "tenant-a",
                "asset_id": "asset-1",
                "delivered_command_ids": ["cmd-1"],
                "audit_events": [{
                    "event": "delivered",
                    "command_id": "cmd-1",
                    "pending_action_id": "pending-1",
                    "action": "isolate",
                    "target": "asset-1",
                    "asset_id": "asset-1",
                    "decision_id": "decision-1",
                    "detection_id": "detection-1",
                    "actor": "agent",
                    "detail": "pulled by agent (single-use)",
                }],
            }

        result = outbox.execute_operation_on_connection(
            connection,
            tenant_id="tenant-a",
            idempotency_key="poll-1",
            request_hash="sha256:poll-1",
            handler=deliver,
            now=100,
        )
        assert result.status == "completed"
        assert connection.execute(
            "SELECT status FROM agent_commands WHERE id='cmd-1'"
        ).fetchone()["status"] == "delivered"
        assert connection.execute(
            "SELECT COUNT(*) FROM cg_operations"
        ).fetchone()[0] == 1
        events = connection.execute(
            "SELECT event_type, tenant_id, payload_json FROM cg_outbox ORDER BY sequence"
        ).fetchall()
        assert [(row["event_type"], row["tenant_id"]) for row in events] == [
            ("operation_intent", "tenant-a"),
            ("operation_completed", "tenant-a"),
        ]
        completion = json.loads(events[1]["payload_json"])
        audit_events = completion["result"]["audit_events"]
        assert audit_events == [{
            "event": "delivered",
            "command_id": "cmd-1",
            "pending_action_id": "pending-1",
            "action": "isolate",
            "target": "asset-1",
            "asset_id": "asset-1",
            "decision_id": "decision-1",
            "detection_id": "detection-1",
            "actor": "agent",
            "detail": "pulled by agent (single-use)",
        }]
    finally:
        connection.close()


def test_live_operation_failure_rolls_back_command_state_and_outbox(tmp_path):
    path, outbox = setup_database(tmp_path)
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        def crash(conn, _operation_id):
            conn.execute(
                "UPDATE agent_commands SET status='delivered' WHERE id='cmd-1'"
            )
            raise RuntimeError("simulated crash before commit")

        with pytest.raises(RuntimeError, match="simulated crash"):
            outbox.execute_operation_on_connection(
                connection,
                tenant_id="tenant-a",
                idempotency_key="poll-crash",
                request_hash="sha256:poll-crash",
                handler=crash,
            )
        assert connection.execute(
            "SELECT status FROM agent_commands WHERE id='cmd-1'"
        ).fetchone()["status"] == "queued"
        assert connection.execute("SELECT COUNT(*) FROM cg_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM cg_outbox").fetchone()[0] == 0
    finally:
        connection.close()


def test_live_operation_rejects_connection_with_existing_transaction(tmp_path):
    path, outbox = setup_database(tmp_path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE agent_commands SET status='queued' WHERE id='cmd-1'")
        with pytest.raises(RuntimeError, match="fresh transaction"):
            outbox.execute_operation_on_connection(
                connection,
                tenant_id="tenant-a",
                idempotency_key="poll-nested",
                request_hash="sha256:nested",
                handler=lambda conn, _operation_id: {"ok": True},
            )
    finally:
        connection.rollback()
        connection.close()



def test_gateway_patch_preserves_tenant_fail_closed_and_per_command_audit_schema():
    from gateway_patches.agent_commands_audit import PATCH_MARKER, patch_source

    original = (
        '@app.get("/v1/agent/commands")\n'
        'async def agent_commands(asset_id: str):\n'
        '    return {}\n'
        '\n\nclass CommandResultIn(\n'
    )
    patched = patch_source(original)
    assert PATCH_MARKER in patched
    assert 'requires an authenticated tenant context' in patched
    for field in (
        '"pending_action_id"', '"target"', '"decision_id"',
        '"detection_id"', '"actor"', '"detail"', '"result_ok"',
        '"audit_events": audit_events',
    ):
        assert field in patched
