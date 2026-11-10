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

    restored_path = tmp_path / "restored" / "audit.jsonl"
    restored = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "restore_audit_checkpoint.py"),
            "--snapshot", str(snapshot),
            "--destination", str(restored_path),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert restored.returncode == 0, restored.stderr
    assert restored_path.read_bytes() == snapshot.read_bytes()

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



def test_checkpoint_cli_loads_key_from_private_credentials_store(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    key = "c3" * 32
    credentials = data_dir / "credentials.json"
    credentials.write_text(
        json.dumps({"audit_checkpoint_key_hex": key}),
        encoding="utf-8",
    )
    credentials.chmod(0o600)
    source = tmp_path / "source.jsonl"
    source.write_text("", encoding="utf-8")
    snapshot = tmp_path / "offhost" / "snapshot.jsonl"

    env = os.environ.copy()
    env.pop("CG_AUDIT_CHECKPOINT_KEY_HEX", None)
    env["CG_DATA_DIR"] = str(data_dir)

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



def test_audit_checkpoint_key_export_writes_private_file_without_printing_secret(tmp_path):
    data_dir = tmp_path / "controller-data"
    data_dir.mkdir(mode=0o700)
    key = "ab" * 32
    credentials = data_dir / "credentials.json"
    credentials.write_text(json.dumps({"audit_checkpoint_key_hex": key}), encoding="utf-8")
    credentials.chmod(0o600)
    recovery_dir = tmp_path / "offhost-secrets"
    recovery_dir.mkdir(mode=0o700)
    output = recovery_dir / "audit-checkpoint.key"

    exported = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "export_audit_checkpoint_key.py"),
            "--data-dir", str(data_dir),
            "--out", str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert exported.returncode == 0, exported.stderr
    assert output.read_text(encoding="ascii") == key + "\n"
    assert output.stat().st_mode & 0o777 == 0o600
    assert key not in exported.stdout
