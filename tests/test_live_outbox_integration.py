"""Tests proving live gateway mutations share the outbox SQLite transaction."""
from __future__ import annotations

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
            "SELECT event_type, tenant_id FROM cg_outbox ORDER BY sequence"
        ).fetchall()
        assert [(row["event_type"], row["tenant_id"]) for row in events] == [
            ("operation_intent", "tenant-a"),
            ("operation_completed", "tenant-a"),
        ]
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
