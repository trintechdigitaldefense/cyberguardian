from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "enroll_agent.py"


def _run(data_dir: Path, *args: str):
    env = os.environ.copy()
    env["CG_DATA_DIR"] = str(data_dir)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
        check=False,
    )


def test_agent_enrollment_rotation_and_revocation(tmp_path):
    data_dir = tmp_path / "controller-data"
    first = _run(data_dir, "--asset-id", "host-1", "--tenant-id", "tenant-1")
    assert first.returncode == 0, first.stderr
    store = data_dir / "agent_credentials.json"
    assert store.is_file()
    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.stat().st_mode) == 0o600

    initial = json.loads(store.read_text())["agents"]["host-1"]
    assert initial["status"] == "active"
    assert initial["tenant_id"] == "tenant-1"
    assert all(initial.get(k) for k in ("api_key", "identity_secret", "command_secret"))

    duplicate = _run(data_dir, "--asset-id", "host-1", "--tenant-id", "tenant-1")
    assert duplicate.returncode == 2

    # Omitting tenant-id during rotation must not silently move the asset.
    rotated = _run(data_dir, "--asset-id", "host-1", "--rotate")
    assert rotated.returncode == 0, rotated.stderr
    after_rotation = json.loads(store.read_text())["agents"]["host-1"]
    assert after_rotation["status"] == "active"
    assert after_rotation["tenant_id"] == "tenant-1"
    for key in ("api_key", "identity_secret", "command_secret"):
        assert after_rotation[key] != initial[key]

    revoked = _run(data_dir, "--asset-id", "host-1", "--revoke")
    assert revoked.returncode == 0, revoked.stderr
    final = json.loads(store.read_text())["agents"]["host-1"]
    assert final["status"] == "revoked"
    assert final.get("revoked_at")


def test_revoked_agent_can_be_reenrolled_with_fresh_credentials(tmp_path):
    data_dir = tmp_path / "controller-data"
    first = _run(data_dir, "--asset-id", "host-2", "--tenant-id", "tenant-a")
    assert first.returncode == 0, first.stderr
    store = data_dir / "agent_credentials.json"
    initial = json.loads(store.read_text())["agents"]["host-2"]

    revoked = _run(data_dir, "--asset-id", "host-2", "--revoke")
    assert revoked.returncode == 0, revoked.stderr
    blocked = _run(data_dir, "--asset-id", "host-2")
    assert blocked.returncode == 0, blocked.stderr
    renewed = json.loads(store.read_text())["agents"]["host-2"]
    assert renewed["status"] == "active"
    assert renewed["tenant_id"] == "tenant-a"
    assert renewed["api_key"] != initial["api_key"]
    assert renewed["identity_secret"] != initial["identity_secret"]
    assert renewed["command_secret"] != initial["command_secret"]


def test_enrollment_rejects_unsafe_asset_and_tenant_identifiers(tmp_path):
    data_dir = tmp_path / "controller-data"
    bad_asset = _run(data_dir, "--asset-id", "../other-tenant")
    assert bad_asset.returncode == 2
    assert not (data_dir / "agent_credentials.json").exists()

    bad_tenant = _run(data_dir, "--asset-id", "host-3", "--tenant-id", "tenant/a")
    assert bad_tenant.returncode == 2
    assert not (data_dir / "agent_credentials.json").exists()


def test_corrupt_enrollment_store_is_not_treated_as_empty(tmp_path):
    data_dir = tmp_path / "controller-data"
    data_dir.mkdir(mode=0o700)
    store = data_dir / "agent_credentials.json"
    original = b'{"agents": '
    store.write_bytes(original)

    attempted = _run(data_dir, "--asset-id", "host-new", "--tenant-id", "tenant-new")
    assert attempted.returncode != 0
    assert store.read_bytes() == original



def test_enrollment_can_write_protected_agent_environment_file(tmp_path):
    data_dir = tmp_path / "controller-data"
    env_dir = tmp_path / "agent-config"
    env_dir.mkdir(mode=0o700)
    env_file = env_dir / "agent.env"

    result = _run(
        data_dir,
        "--asset-id", "host-local",
        "--tenant-id", "tenant-local",
        "--env-file", str(env_file),
    )
    assert result.returncode == 0, result.stderr
    assert "protected environment file written" in result.stdout
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    env_text = env_file.read_text()
    assert "CYBERGUARDIAN_API=http://127.0.0.1:8080" in env_text
    assert "CYBERGUARDIAN_ASSET_ID=host-local" in env_text
    assert "CYBERGUARDIAN_TENANT=tenant-local" in env_text
    assert "CG_AGENT_IDENTITY_SECRET=" in env_text
    assert "CG_COMMAND_SIGNING_SECRET=" in env_text
    assert "cg_agent_" not in result.stdout


def test_enrollment_requires_https_for_non_loopback_controller(tmp_path):
    result = _run(
        tmp_path / "controller-data",
        "--asset-id", "host-remote",
        "--tenant-id", "tenant-remote",
        "--api-url", "http://192.0.2.10:8080",
    )
    assert result.returncode == 2
    assert "must use HTTPS" in result.stderr
    assert not (tmp_path / "controller-data" / "agent_credentials.json").exists()
