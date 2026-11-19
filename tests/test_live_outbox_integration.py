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




def test_patched_gateway_route_source_compiles():
    """Generated route must be valid Python before it is assembled into the gateway."""
    from gateway_patches.agent_commands_audit import patch_source

    original = (
        'from pydantic import BaseModel\n\n'
        '@app.get("/v1/agent/commands")\n'
        'async def agent_commands(asset_id: str):\n'
        '    return {}\n'
        '\n\nclass CommandResultIn(BaseModel):\n    pass\n'
    )
    patched = patch_source(original)
    compile(patched, "patched_gateway_route.py", "exec")


def test_gateway_patch_preserves_tenant_fail_closed_and_per_command_audit_schema():
    from gateway_patches.agent_commands_audit import PATCH_MARKER, patch_source

    original = (
        'from pydantic import BaseModel\n\n'
        '@app.get("/v1/agent/commands")\n'
        'async def agent_commands(asset_id: str):\n'
        '    return {}\n'
        '\n\nclass CommandResultIn(BaseModel):\n    pass\n'
    )
    patched = patch_source(original)
    assert PATCH_MARKER in patched
    assert 'SELECT tenant_id FROM assets WHERE asset_id=?' in patched
    assert 'Agent command asset is not registered' in patched
    for field in (
        '"pending_action_id"', '"target"', '"decision_id"',
        '"detection_id"', '"actor"', '"detail"', '"result_ok"',
        '"audit_events": audit_events',
    ):
        assert field in patched



def test_patched_gateway_route_returns_commands_and_persists_tenant_audit(tmp_path):
    import asyncio
    import contextlib
    import json
    import time
    import uuid

    from gateway_patches.agent_commands_audit import patch_source

    class FakeApp:
        def get(self, _path):
            return lambda function: function

    class FakeHTTPException(Exception):
        def __init__(self, status_code, detail):
            super().__init__(detail)
            self.status_code = status_code

    class AgentIdentity:
        @staticmethod
        def assert_not_admin_key_on_agent(key):
            return (key == "agent-key", "invalid agent key")

    database = tmp_path / "gateway-route.sqlite3"

    @contextlib.contextmanager
    def db():
        connection = sqlite3.connect(database, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE assets (asset_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)"
        )
        connection.execute(
            """CREATE TABLE agent_commands (
                id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, status TEXT NOT NULL,
                created_at REAL NOT NULL, parameters TEXT, completed_at REAL,
                delivered_at REAL, pending_action_id TEXT, action TEXT, target TEXT,
                decision_id TEXT, detection_id TEXT, signature TEXT,
                signature_key_id TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO assets(asset_id, tenant_id) VALUES ('asset-a', 'tenant-a')"
        )
        connection.execute(
            """INSERT INTO agent_commands
               (id, asset_id, status, created_at, parameters, pending_action_id,
                action, target, decision_id, detection_id, signature, signature_key_id)
               VALUES ('cmd-deliver', 'asset-a', 'queued', 1, ?, 'pending-1',
                       'isolate', 'host-a', 'decision-1', 'detection-1',
                       'signed-envelope', 'key-1')""",
            (json.dumps({"_expires_at": time.time() + 3600}),),
        )
        connection.execute(
            """INSERT INTO agent_commands
               (id, asset_id, status, created_at, parameters, pending_action_id,
                action, target)
               VALUES ('cmd-expire', 'asset-a', 'queued', 2, ?, 'pending-2',
                       'terminate', 'host-b')""",
            (json.dumps({"_expires_at": 1}),),
        )

    original = (
        'from pydantic import BaseModel\n\n'
        '@app.get("/v1/agent/commands")\n'
        'async def agent_commands(asset_id: str):\n'
        '    return {}\n'
        '\n\nclass CommandResultIn(BaseModel):\n    pass\n'
    )
    patched = patch_source(original)
    namespace = {
        "Path": Path,
        "DB_PATH": database,
        "app": FakeApp(),
        "Depends": lambda value: value,
        "require_api_key": object(),
        "_agent_id": AgentIdentity(),
        "HTTPException": FakeHTTPException,
        "time": time,
        "json": json,
        "uuid": uuid,
        "db": db,
    }
    exec(compile(patched, "patched_gateway_route.py", "exec"), namespace)
    route = namespace["agent_commands"]

    with pytest.raises(FakeHTTPException) as invalid_key:
        asyncio.run(route("asset-a", x_api_key="admin-key"))
    assert invalid_key.value.status_code == 403

    response = asyncio.run(route("asset-a", x_api_key="agent-key"))
    assert response["count"] == 1
    assert response["commands"][0]["id"] == "cmd-deliver"
    assert response["commands"][0]["signature"] == "signed-envelope"
    assert response["commands"][0]["signature_key_id"] == "key-1"

    with sqlite3.connect(database) as connection:
        statuses = dict(connection.execute(
            "SELECT id, status FROM agent_commands"
        ).fetchall())
        assert statuses == {"cmd-deliver": "delivered", "cmd-expire": "expired"}
        completion = connection.execute(
            "SELECT payload_json FROM cg_outbox WHERE event_type='operation_completed'"
        ).fetchone()
    payload = json.loads(completion[0])
    assert payload["tenant_id"] == "tenant-a"
    events = payload["result"]["audit_events"]
    assert [event["event"] for event in events] == ["delivered", "expired"]
    delivered = events[0]
    assert delivered["pending_action_id"] == "pending-1"
    assert delivered["target"] == "host-a"
    assert delivered["decision_id"] == "decision-1"
    assert delivered["detection_id"] == "detection-1"
    expired = events[1]
    assert expired["pending_action_id"] == "pending-2"
    assert expired["target"] == "host-b"
    assert expired["result_ok"] == 0


def test_patched_gateway_route_rejects_unregistered_or_unattributed_assets(tmp_path):
    import asyncio
    import contextlib
    import json
    import time
    import uuid

    from gateway_patches.agent_commands_audit import patch_source

    class FakeApp:
        def get(self, _path):
            return lambda function: function

    class FakeHTTPException(Exception):
        def __init__(self, status_code, detail):
            super().__init__(detail)
            self.status_code = status_code

    class AgentIdentity:
        @staticmethod
        def assert_not_admin_key_on_agent(_key):
            return (True, "")

    database = tmp_path / "gateway-tenant.sqlite3"

    @contextlib.contextmanager
    def db():
        connection = sqlite3.connect(database, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE assets (asset_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE agent_commands (id TEXT PRIMARY KEY, asset_id TEXT, status TEXT, "
            "created_at REAL, parameters TEXT, completed_at REAL, delivered_at REAL)"
        )
        connection.execute(
            "INSERT INTO assets(asset_id, tenant_id) VALUES ('asset-empty', '')"
        )

    original = (
        'from pydantic import BaseModel\n\n'
        '@app.get("/v1/agent/commands")\n'
        'async def agent_commands(asset_id: str):\n'
        '    return {}\n'
        '\n\nclass CommandResultIn(BaseModel):\n    pass\n'
    )
    namespace = {
        "Path": Path, "DB_PATH": database, "app": FakeApp(),
        "Depends": lambda value: value, "require_api_key": object(),
        "_agent_id": AgentIdentity(), "HTTPException": FakeHTTPException,
        "time": time, "json": json, "uuid": uuid, "db": db,
    }
    exec(compile(patch_source(original), "patched_gateway_route.py", "exec"), namespace)
    route = namespace["agent_commands"]

    with pytest.raises(FakeHTTPException) as missing:
        asyncio.run(route("unknown", x_api_key="agent-key"))
    assert missing.value.status_code == 404

    with pytest.raises(FakeHTTPException) as unattributed:
        asyncio.run(route("asset-empty", x_api_key="agent-key"))
    assert unattributed.value.status_code == 403
