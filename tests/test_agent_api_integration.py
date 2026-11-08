from __future__ import annotations

import importlib
import json
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

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

    record = {
        "tenant_id": "tenant-a",
        "api_key": "agent-key-host-a",
        "identity_secret": "identity-secret-host-a",
        "command_secret": "command-secret-host-a",
        "status": "active",
    }
    agent_credentials.write_agent_credentials({"host-a": record})

    fingerprint = agent_identity.host_fingerprint("host-a", "linux-test", "machine-a")
    identity_ts = time.time()
    identity_sig = agent_identity.sign_registration("host-a", fingerprint, identity_ts)

    headers = {"X-API-Key": record["api_key"], "X-Tenant-ID": "tenant-a"}
    with TestClient(main.app) as client:
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

        reported = client.post(
            "/v1/agent/command-result",
            headers=headers,
            json={
                "command_id": command["id"],
                "asset_id": "host-a",
                "action": command["action"],
                "target": command["target"],
                "ok": True,
                "detail": "integration-test-complete",
                "result": {"test": True},
            },
        )
        assert reported.status_code == 200, reported.text

        revoked_record = dict(record)
        revoked_record["status"] = "revoked"
        agent_credentials.write_agent_credentials({"host-a": revoked_record})
        revoked_poll = client.get("/v1/agent/commands?asset_id=host-a", headers=headers)
        assert revoked_poll.status_code == 403
