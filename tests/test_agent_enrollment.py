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

    initial = json.loads(store.read_text())["agents"]["host-1"]
    assert initial["status"] == "active"
    assert initial["tenant_id"] == "tenant-1"
    assert all(initial.get(k) for k in ("api_key", "identity_secret", "command_secret"))

    duplicate = _run(data_dir, "--asset-id", "host-1", "--tenant-id", "tenant-1")
    assert duplicate.returncode == 2

    rotated = _run(data_dir, "--asset-id", "host-1", "--tenant-id", "tenant-1", "--rotate")
    assert rotated.returncode == 0, rotated.stderr
    after_rotation = json.loads(store.read_text())["agents"]["host-1"]
    assert after_rotation["status"] == "active"
    for key in ("api_key", "identity_secret", "command_secret"):
        assert after_rotation[key] != initial[key]

    revoked = _run(data_dir, "--asset-id", "host-1", "--revoke")
    assert revoked.returncode == 0, revoked.stderr
    final = json.loads(store.read_text())["agents"]["host-1"]
    assert final["status"] == "revoked"
    assert final.get("revoked_at")
