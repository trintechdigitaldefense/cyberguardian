"""Release-gate tests for deterministic gateway assembly."""
from __future__ import annotations

import ast
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "control-plane" / "api"


def test_gateway_assembles_and_matches_published_digest() -> None:
    result = subprocess.run(
        [sys.executable, str(API_DIR / "assemble_main.py")],
        cwd=API_DIR,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    gateway = API_DIR / "main_full.py"
    assert gateway.is_file()
    source = gateway.read_bytes()
    assert len(source) >= 20_000
    ast.parse(source.decode("utf-8"), filename=str(gateway))

    checksum_text = (API_DIR / "GATEWAY_SHA256.txt").read_text(encoding="ascii")
    match = re.search(r"^([0-9a-f]{64})\s+main_full\.py\s*$", checksum_text, re.MULTILINE)
    assert match, "GATEWAY_SHA256.txt must declare the expected main_full.py digest"
    assert hashlib.sha256(source).hexdigest() == match.group(1)
