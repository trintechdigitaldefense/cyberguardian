from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "control-plane" / "api"
AGENT = ROOT / "agents" / "linux-ebpf"
sys.path.insert(0, str(API))
sys.path.insert(0, str(AGENT))

from command_signing import sign_envelope
from command_crypto import claim_command, verify_command
import agent_credentials
import agent_identity


def test_controller_signed_envelope_verifies_and_is_single_use(tmp_path):
    secret = "controller-agent-command-secret"
    now = time.time()
    queued = {
        "id": "cmd-1",
        "asset_id": "host-a",
        "action": "kill_process",
        "target": "4321",
        "pending_action_id": "approval-7",
        "parameters": {"pid": 4321, "_expires_at": now + 600, "_approval_id": "approval-7"},
    }
    signed = sign_envelope(queued, tenant_id="tenant-a", secret=secret)
    ok, reason = verify_command(
        signed, secret, expected_asset_id="host-a", expected_tenant_id="tenant-a"
    )
    assert ok, reason
    state = tmp_path / "replay.sqlite3"
    assert claim_command(signed, state)
    assert not claim_command(signed, state)


def test_controller_refuses_unapproved_disruptive_command():
    queued = {
        "id": "cmd-2",
        "asset_id": "host-a",
        "action": "isolate_host",
        "target": "host-a",
        "parameters": {"_expires_at": time.time() + 300},
    }
    try:
        sign_envelope(queued, tenant_id="tenant-a", secret="secret")
    except ValueError as exc:
        assert "approval reference" in str(exc)
    else:
        raise AssertionError("disruptive command without approval was signed")



def test_allowlisted_disruptive_command_has_auditable_approval_reference():
    queued = {
        "id": "cmd-allowlisted",
        "asset_id": "host-a",
        "action": "block_ip",
        "target": "192.0.2.10",
        "decision_id": "decision-123",
        "reason": "approved by scoped auto allowlist",
        "parameters": {"ip": "192.0.2.10", "_expires_at": time.time() + 300},
    }
    signed = sign_envelope(queued, tenant_id="tenant-a", secret="secret")
    assert signed["approval_ref"] == "allowlist:decision-123"
    ok, reason = verify_command(signed, "secret")
    assert ok, reason

def test_per_agent_identity_is_bound_to_active_enrollment(tmp_path, monkeypatch):
    store = tmp_path / "agent_credentials.json"
    store.write_text(json.dumps({
        "agents": {
            "host-a": {
                "tenant_id": "tenant-a",
                "api_key": "agent-api-key",
                "identity_secret": "agent-identity-secret",
                "command_secret": "agent-command-secret",
                "status": "active",
            }
        }
    }))
    monkeypatch.setattr(agent_credentials, "STORE", store)
    monkeypatch.setenv("CG_PRODUCTION", "1")
    fingerprint = agent_identity.host_fingerprint("host-a", "linux-test", "machine-1")
    timestamp = time.time()
    signature = agent_identity.sign_registration("host-a", fingerprint, timestamp)
    ok, reason = agent_identity.verify_registration("host-a", fingerprint, timestamp, signature)
    assert ok, reason
    assert agent_identity.assert_not_admin_key_on_agent("agent-api-key")[0]

    data = json.loads(store.read_text())
    data["agents"]["host-a"]["status"] = "revoked"
    store.write_text(json.dumps(data))
    ok, reason = agent_identity.verify_registration("host-a", fingerprint, timestamp, signature)
    assert not ok and reason == "agent_identity_secret_required"
    assert not agent_identity.assert_not_admin_key_on_agent("agent-api-key")[0]
