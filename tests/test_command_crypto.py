import os, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents" / "linux-ebpf"))
from command_crypto import sign_command, verify_command

def test_sign_verify_roundtrip():
    os.environ["CG_COMMAND_SIGNING_SECRET"] = "test-secret-123"
    cmd = {
        "command_id": "c1", "asset_id": "host1", "tenant_id": "default",
        "action": "kill_process", "target": "1234", "parameters": {"pid": 1234},
        "expires_at": time.time() + 600, "approval_ref": "a1", "nonce": "abc",
    }
    cmd["signature"] = sign_command(cmd)
    ok, why = verify_command(cmd)
    assert ok, why

def test_reject_bad_sig():
    os.environ["CG_COMMAND_SIGNING_SECRET"] = "test-secret-123"
    os.environ["CG_REQUIRE_COMMAND_SIG"] = "1"
    cmd = {
        "command_id": "c1", "asset_id": "h", "action": "block_ip", "target": "1.2.3.4",
        "parameters": {}, "expires_at": time.time() + 60, "approval_ref": "", "nonce": "n",
        "signature": "deadbeef",
    }
    ok, why = verify_command(cmd)
    assert not ok and why == "bad_signature"

def test_reject_expired():
    os.environ["CG_COMMAND_SIGNING_SECRET"] = "test-secret-123"
    cmd = {
        "command_id": "c1", "asset_id": "h", "action": "block_ip", "target": "1.2.3.4",
        "parameters": {}, "expires_at": time.time() - 10, "approval_ref": "", "nonce": "n",
    }
    cmd["signature"] = sign_command(cmd)
    ok, why = verify_command(cmd)
    assert not ok and why == "command_expired"
