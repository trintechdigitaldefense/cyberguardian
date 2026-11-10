from __future__ import annotations

import importlib
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "control-plane" / "api"
AGENT = ROOT / "agents" / "linux-ebpf"
sys.path.insert(0, str(API))
sys.path.insert(0, str(AGENT))


def test_enrolled_agent_receives_only_tenant_bound_signed_commands(tmp_path, monkeypatch):
    monkeypatch.setenv("CG_DATA_DIR", str(tmp_path / "controller-data"))
    monkeypatch.setenv("CG_PRODUCTION", "1")
    monkeypatch.setenv("CG_REQUIRE_AGENT_IDENTITY", "1")
    monkeypatch.setenv("CG_REQUIRE_COMMAND_SIG", "1")
    monkeypatch.setenv("CYBERGUARDIAN_API_KEY", "admin-key-" + "a" * 40)
    monkeypatch.setenv("CG_DASHBOARD_API_KEY", "dashboard-key-" + "b" * 40)
    monkeypatch.setenv("CG_NAD_API_KEY", "nad-key-" + "c" * 40)
    monkeypatch.setenv("CG_OPERATOR_ASSERTION_SECRET", "operator-secret-" + "d" * 40)
    monkeypatch.setenv("DECISION_SERVICE_API_KEY", "decision-key-" + "e" * 40)

    import runtime_paths
    import agent_credentials
    import agent_identity

    importlib.reload(runtime_paths)
    importlib.reload(agent_credentials)
    importlib.reload(agent_identity)

    import main
    importlib.reload(main)

    main._mod.DB_PATH = tmp_path / "gateway.sqlite3"
    main._mod.GATE_CFG = tmp_path / "gate_config.json"
    main._mod.CREDS_PATH = tmp_path / "credentials.json"
    main._mod.CREDS_PATH.write_text(
        json.dumps({
            "api_key": "admin-key-" + "a" * 40,
            "audit_checkpoint_key_hex": "f" * 64,
        }),
        encoding="utf-8",
    )
    main._mod.CREDS_PATH.chmod(0o600)

    record = {
        "tenant_id": "tenant-a",
        "api_key": "agent-key-host-a",
        "identity_secret": "identity-secret-host-a",
        "command_secret": "command-secret-host-a",
        "status": "active",
    }
    record_b = {
        "tenant_id": "tenant-b",
        "api_key": "agent-key-host-b",
        "identity_secret": "identity-secret-host-b",
        "command_secret": "command-secret-host-b",
        "status": "active",
    }
    agent_credentials.write_agent_credentials({"host-a": record, "host-b": record_b})

    fingerprint = agent_identity.host_fingerprint("host-a", "linux-test", "machine-a")
    identity_ts = time.time()
    identity_sig = agent_identity.sign_registration("host-a", fingerprint, identity_ts)

    headers = {"X-API-Key": record["api_key"], "X-Tenant-ID": "tenant-a"}
    with TestClient(main.app) as client:
        invalid_identity = client.post(
            "/v1/assets/register",
            headers=headers,
            json={
                "asset_id": "host-a",
                "tenant_id": "tenant-a",
                "hostname": "host-a",
                "os": "linux-test",
                "machine_id": "machine-a",
                "fingerprint": fingerprint,
                "identity_ts": identity_ts,
                "identity_sig": "0" * 64,
            },
        )
        assert invalid_identity.status_code == 401, invalid_identity.text

        admin_key_registration = client.post(
            "/v1/assets/register",
            headers={"X-API-Key": "admin-key-" + "a" * 40, "X-Tenant-ID": "tenant-a"},
            json={
                "asset_id": "host-a",
                "tenant_id": "tenant-a",
                "hostname": "host-a",
                "os": "linux-test",
                "machine_id": "machine-a",
                "fingerprint": fingerprint,
                "identity_ts": identity_ts,
                "identity_sig": identity_sig,
            },
        )
        assert admin_key_registration.status_code == 403, admin_key_registration.text

        registered = client.post(
            "/v1/assets/register",
            headers=headers,
            json={
                "asset_id": "host-a",
                "tenant_id": "tenant-a",
                "hostname": "host-a",
                "os": "linux-test",
                "machine_id": "machine-a",
                "fingerprint": fingerprint,
                "identity_ts": identity_ts,
                "identity_sig": identity_sig,
            },
        )
        assert registered.status_code == 200, registered.text

        fingerprint_b = agent_identity.host_fingerprint("host-b", "linux-test", "machine-b")
        identity_ts_b = time.time()
        identity_sig_b = agent_identity.sign_registration("host-b", fingerprint_b, identity_ts_b)
        headers_b = {"X-API-Key": record_b["api_key"], "X-Tenant-ID": "tenant-b"}
        registered_b = client.post(
            "/v1/assets/register",
            headers=headers_b,
            json={
                "asset_id": "host-b",
                "tenant_id": "tenant-b",
                "hostname": "host-b",
                "os": "linux-test",
                "machine_id": "machine-b",
                "fingerprint": fingerprint_b,
                "identity_ts": identity_ts_b,
                "identity_sig": identity_sig_b,
            },
        )
        assert registered_b.status_code == 200, registered_b.text

        # The shared NAD service key may submit detections only for the
        # tenant bound to the registered asset, never a caller-selected tenant.
        def nad_request(tenant_header=None):
            body = json.dumps({"asset_id": "host-a", "source": "nad-test"}).encode("utf-8")
            request_headers = [
                (b"x-api-key", ("nad-key-" + "c" * 40).encode("utf-8")),
                (b"content-type", b"application/json"),
            ]
            if tenant_header:
                request_headers.append((b"x-tenant-id", tenant_header.encode("utf-8")))
            scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/v1/detections",
                "raw_path": b"/v1/detections",
                "query_string": b"",
                "headers": request_headers,
                "client": ("127.0.0.1", 1234),
                "server": ("testserver", 80),
            }
            sent = False

            async def receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.disconnect"}

            return Request(scope, receive)

        async def capture_nad_tenant(request):
            return {
                "tenant_id": request.state.tenant_id,
                "header_tenant": request.headers.get("X-Tenant-ID"),
            }

        async def nad_auth_chain(request):
            return await main._verify_dashboard_operator(request, capture_nad_tenant)

        nad_scoped = asyncio.run(
            main._agent_scope_and_command_signing(nad_request(), nad_auth_chain)
        )
        assert nad_scoped == {"tenant_id": "tenant-a", "header_tenant": "tenant-a"}
        nad_spoofed = asyncio.run(
            main._agent_scope_and_command_signing(nad_request("tenant-b"), nad_auth_chain)
        )
        assert nad_spoofed.status_code == 403

        with main._mod.db() as conn:
            first_seen = conn.execute(
                "SELECT last_seen FROM assets WHERE asset_id=?", ("host-a",)
            ).fetchone()["last_seen"]

        # A restarted agent replays its signed registration as its heartbeat.
        # It must refresh last_seen without creating a second inventory row.
        time.sleep(0.01)
        reconnect_ts = time.time()
        reconnect_sig = agent_identity.sign_registration("host-a", fingerprint, reconnect_ts)
        reconnected = client.post(
            "/v1/assets/register",
            headers=headers,
            json={
                "asset_id": "host-a",
                "tenant_id": "tenant-a",
                "hostname": "host-a",
                "os": "linux-test",
                "machine_id": "machine-a",
                "fingerprint": fingerprint,
                "identity_ts": reconnect_ts,
                "identity_sig": reconnect_sig,
            },
        )
        assert reconnected.status_code == 200, reconnected.text
        with main._mod.db() as conn:
            rows = conn.execute(
                "SELECT last_seen FROM assets WHERE asset_id=?", ("host-a",)
            ).fetchall()
            assert len(rows) == 1
            assert rows[0]["last_seen"] > first_seen

        wrong_tenant_registration = client.post(
            "/v1/assets/register",
            headers={**headers, "X-Tenant-ID": "tenant-b"},
            json={
                "asset_id": "host-a",
                "tenant_id": "tenant-b",
                "hostname": "host-a",
                "os": "linux-test",
                "machine_id": "machine-a",
                "fingerprint": fingerprint,
                "identity_ts": reconnect_ts + 1,
                "identity_sig": agent_identity.sign_registration(
                    "host-a", fingerprint, reconnect_ts + 1
                ),
            },
        )
        assert wrong_tenant_registration.status_code == 403

        main._mod.queue_agent_command(
            asset_id="host-a",
            action="kill_process",
            target="4321",
            parameters={"pid": 4321},
            pending_action_id="approval-a",
            ttl_seconds=300,
        )
        polled = client.get("/v1/agent/commands?asset_id=host-a", headers=headers)
        assert polled.status_code == 200, polled.text
        payload = polled.json()
        assert payload["count"] == 1
        command = payload["commands"][0]
        from command_crypto import verify_command

        ok, reason = verify_command(
            command,
            record["command_secret"],
            expected_asset_id="host-a",
            expected_tenant_id="tenant-a",
        )
        assert ok, reason

        main._mod.queue_agent_command(
            asset_id="host-b",
            action="kill_process",
            target="9876",
            parameters={"pid": 9876},
            pending_action_id="approval-b",
            ttl_seconds=300,
        )
        isolated_poll = client.get(
            "/v1/agent/commands?asset_id=host-b",
            headers=headers_b,
        )
        assert isolated_poll.status_code == 200, isolated_poll.text
        isolated_payload = isolated_poll.json()
        assert isolated_payload["count"] == 1
        isolated_command = isolated_payload["commands"][0]
        ok_b, reason_b = verify_command(
            isolated_command,
            record_b["command_secret"],
            expected_asset_id="host-b",
            expected_tenant_id="tenant-b",
        )
        assert ok_b, reason_b
        cross_tenant_poll = client.get(
            "/v1/agent/commands?asset_id=host-b",
            headers=headers,
        )
        assert cross_tenant_poll.status_code == 403

        wrong_tenant = client.get(
            "/v1/agent/commands?asset_id=host-a",
            headers={"X-API-Key": record["api_key"], "X-Tenant-ID": "tenant-b"},
        )
        assert wrong_tenant.status_code == 403

        wrong_asset = client.get(
            "/v1/agent/commands?asset_id=other-host",
            headers=headers,
        )
        assert wrong_asset.status_code == 403

        # An agent key cannot be reused as a general API key to read fleet or
        # operator configuration belonging to another tenant.
        fleet_read = client.get("/v1/assets?tenant_id=tenant-b", headers=headers)
        assert fleet_read.status_code == 403
        admin_read = client.get("/v1/client-mode", headers=headers)
        assert admin_read.status_code == 403

        command_result_payload = {
            "command_id": command["id"],
            "asset_id": "host-a",
            "action": command["action"],
            "target": command["target"],
            "ok": True,
            "detail": "integration-test-complete",
            "result": {"test": True},
        }
        canonical_event = json.dumps(
            {
                "kind": "POST",
                "path": "/v1/agent/command-result",
                "payload": command_result_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        event_id = hashlib.sha256(canonical_event.encode("utf-8")).hexdigest()
        idempotent_headers = {**headers, "X-CG-Event-ID": event_id}
        mismatched_event = client.post(
            "/v1/agent/command-result",
            headers={**headers, "X-CG-Event-ID": "0" * 64},
            json=command_result_payload,
        )
        assert mismatched_event.status_code == 400, mismatched_event.text
        reported = client.post(
            "/v1/agent/command-result",
            headers=idempotent_headers,
            json=command_result_payload,
        )
        assert reported.status_code == 200, reported.text
        with main._mod.db() as conn:
            conn.execute(
                "UPDATE cg_agent_idempotency SET created_at=? WHERE tenant_id=? AND asset_id=? AND event_id=?",
                (time.time() - 365 * 24 * 60 * 60, "tenant-a", "host-a", event_id),
            )
        replayed = client.post(
            "/v1/agent/command-result",
            headers=idempotent_headers,
            json=command_result_payload,
        )
        assert replayed.status_code == reported.status_code, replayed.text
        assert replayed.content == reported.content
        assert replayed.headers.get("x-cg-idempotent-replay") == "true"
        with main._mod.db() as conn:
            idempotency_rows = conn.execute(
                "SELECT COUNT(*) FROM cg_agent_idempotency WHERE tenant_id=? AND asset_id=? AND event_id=?",
                ("tenant-a", "host-a", event_id),
            ).fetchone()[0]
            assert idempotency_rows == 1

        revoked_record = dict(record)
        revoked_record["status"] = "revoked"
        agent_credentials.write_agent_credentials({"host-a": revoked_record})
        revoked_poll = client.get("/v1/agent/commands?asset_id=host-a", headers=headers)
        assert revoked_poll.status_code == 403

        revoked_ts = time.time()
        revoked_registration = client.post(
            "/v1/assets/register",
            headers=headers,
            json={
                "asset_id": "host-a",
                "tenant_id": "tenant-a",
                "hostname": "host-a",
                "os": "linux-test",
                "machine_id": "machine-a",
                "fingerprint": fingerprint,
                "identity_ts": revoked_ts,
                "identity_sig": agent_identity.sign_registration(
                    "host-a", fingerprint, revoked_ts
                ),
            },
        )
        assert revoked_registration.status_code == 403, revoked_registration.text

        revoked_result = client.post(
            "/v1/agent/command-result",
            headers=headers,
            json={
                "command_id": command["id"],
                "asset_id": "host-a",
                "action": command["action"],
                "target": command["target"],
                "ok": True,
                "detail": "must-not-be-accepted-after-revocation",
                "result": {"test": True},
            },
        )
        assert revoked_result.status_code == 403, revoked_result.text



def test_gateway_middleware_propagates_verified_tenant_into_issue_memory(tmp_path, monkeypatch):
    main = _load_gateway()
    monkeypatch.setattr(main._issue_memory, "STORE", tmp_path / "issues.jsonl")
    monkeypatch.setattr(main._issue_memory, "ARCHIVE", tmp_path / "issues-archive.jsonl")
    request = SimpleNamespace(
        state=SimpleNamespace(tenant_id="tenant-a"),
        headers={},
    )

    async def create_issue(_request):
        return main._issue_memory.remember_issue(
            "middleware tenant test", "asset-a"
        )

    result = asyncio.run(main._issue_memory_tenant_scope(request, create_issue))
    assert result["tenant_id"] == "tenant-a"
    assert main._issue_memory.list_issues(tenant_id="tenant-a")[0]["id"] == result["id"]
    assert main._issue_memory.list_issues(tenant_id="tenant-b") == []
