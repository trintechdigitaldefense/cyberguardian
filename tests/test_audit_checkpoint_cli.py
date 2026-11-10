from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_export_and_verify_signed_checkpoint_cli(tmp_path):
    source = tmp_path / "source.jsonl"
    snapshot = tmp_path / "independent" / "snapshot.jsonl"
    key = "a1" * 32
    source.write_text("", encoding="utf-8")
    env = os.environ.copy()
    env["CG_AUDIT_CHECKPOINT_KEY_HEX"] = key

    exported = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "export_audit_ledger.py"),
            "--source", str(source),
            "--out", str(snapshot),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert exported.returncode == 0, exported.stderr
    manifest = json.loads(Path(str(snapshot) + ".manifest.json").read_text(encoding="utf-8"))
    assert manifest["algorithm"] == "HMAC-SHA256"

    verified = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_audit_checkpoint.py"),
            "--snapshot", str(snapshot),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["valid"] is True

    wrong_env = env.copy()
    wrong_env["CG_AUDIT_CHECKPOINT_KEY_HEX"] = "b2" * 32
    rejected = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_audit_checkpoint.py"),
            "--snapshot", str(snapshot),
        ],
        cwd=ROOT,
        env=wrong_env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert rejected.returncode == 2
    assert "signature mismatch" in rejected.stderr
