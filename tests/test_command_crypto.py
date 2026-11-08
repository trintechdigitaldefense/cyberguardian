import os, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents" / "linux-ebpf"))
from command_crypto import sign_command, verify_command


def _command():
    return {
        "id": "c1",
        "asset_id": "host1",
        "tenant_id": "tenant-a",
        "action": "kill_process",
        "target": "1234",
        "parameters": {"pid": 1234},
        "expires_at": time.time() + 600,
        "approval_ref": "approval-1",
        "nonce": "0123456789abcdef0123456789abcdef",
    }


def test_sign_verify_roundtrip():
    secret = "test-secret-123"
    cmd = _command()
    cmd["signature"] = sign_command(cmd, secret)
    ok, why = verify_command(cmd, secret, expected_asset_id="host1", expected_tenant_id="tenant-a")
    assert ok, why


def test_reject_bad_signature():
    secret = "test-secret-123"
    cmd = _command()
    cmd["signature"] = "deadbeef"
    ok, why = verify_command(cmd, secret)
    assert not ok and why == "bad_signature"


def test_reject_expired_command():
    secret = "test-secret-123"
    cmd = _command()
    cmd["expires_at"] = time.time() - 10
    cmd["signature"] = sign_command(cmd, secret)
    ok, why = verify_command(cmd, secret)
    assert not ok and why == "command_expired_or_expiry_too_far"


def test_reject_wrong_asset_and_tenant():
    secret = "test-secret-123"
    cmd = _command()
    cmd["signature"] = sign_command(cmd, secret)
    assert verify_command(cmd, secret, expected_asset_id="other-host")[1] == "wrong_asset"
    assert verify_command(cmd, secret, expected_tenant_id="other-tenant")[1] == "wrong_tenant"


def test_reject_tampered_parameters():
    secret = "test-secret-123"
    cmd = _command()
    cmd["signature"] = sign_command(cmd, secret)
    cmd["parameters"]["pid"] = 9999
    ok, why = verify_command(cmd, secret)
    assert not ok and why == "bad_signature"
