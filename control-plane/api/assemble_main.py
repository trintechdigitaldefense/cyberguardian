#!/usr/bin/env python3
"""Assemble and verify the canonical CyberGuardian API gateway source."""
from __future__ import annotations

import ast
import base64
import hashlib
import re
import zlib
from pathlib import Path

from gateway_patches.agent_commands_audit import patch_source
from gateway_patches.decision_service_auth import patch_source as patch_decision_auth
from gateway_patches.cors_config import patch_source as patch_cors

ROOT = Path(__file__).resolve().parent
PARTS_DIR = ROOT / "gateway_z"
CHECKSUM_FILE = ROOT / "GATEWAY_SHA256.txt"
OUTPUT = ROOT / "main_full.py"

# Digest of the original six-part compressed source before deterministic patches.
SOURCE_SHA256 = "39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674"


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def main() -> None:
    parts = sorted(PARTS_DIR.glob("[0-9][0-9].txt"))
    expected_names = [f"{i:02d}.txt" for i in range(6)]
    actual_names = [part.name for part in parts]
    if actual_names != expected_names:
        fail(f"gateway_z chunks incomplete or out of order: {actual_names}")

    try:
        encoded = "".join(part.read_text(encoding="ascii").strip() for part in parts)
        compressed = base64.b64decode(encoded, validate=True)
        original = zlib.decompress(compressed)
        original_text = original.decode("utf-8")
    except (OSError, UnicodeError, ValueError, zlib.error) as exc:
        fail(f"gateway source decoding failed: {exc}")

    original_sha = hashlib.sha256(original).hexdigest()
    if original_sha != SOURCE_SHA256:
        fail(f"canonical source SHA-256 mismatch: expected {SOURCE_SHA256}, got {original_sha}")

    if len(original) < 20_000 or "CyberGuardian API Gateway" not in original_text[:400]:
        fail(f"decoded gateway source failed structural checks (size={len(original)})")

    try:
        source_text = patch_source(original_text)
        source_text = patch_decision_auth(source_text)
        source_text = patch_cors(source_text)
        source = source_text.encode("utf-8")
        ast.parse(source_text, filename="main_full.py")
    except (UnicodeError, SyntaxError, ValueError) as exc:
        fail(f"gateway patch or syntax validation failed: {exc}")

    try:
        checksum_text = CHECKSUM_FILE.read_text(encoding="ascii")
    except OSError as exc:
        fail(f"cannot read {CHECKSUM_FILE.name}: {exc}")

    match = re.search(r"^([0-9a-fA-F]{64})\s+main_full\.py\s*$", checksum_text, re.MULTILINE)
    if not match:
        fail("GATEWAY_SHA256.txt must contain '<64-hex-sha256>  main_full.py'")

    expected_sha = match.group(1).lower()
    actual_sha = hashlib.sha256(source).hexdigest()
    if actual_sha != expected_sha:
        fail(f"assembled gateway SHA-256 mismatch: expected {expected_sha}, got {actual_sha}")

    size_match = re.search(r"^#\s*size\s+(\d+)\s*$", checksum_text, re.MULTILINE)
    if size_match and len(source) != int(size_match.group(1)):
        fail(f"assembled gateway size mismatch: expected {size_match.group(1)}, got {len(source)}")

    temporary = OUTPUT.with_suffix(".py.tmp")
    temporary.write_bytes(source)
    temporary.replace(OUTPUT)
    print(f"OK: {OUTPUT.name} ({len(source)} bytes) sha256={actual_sha}")


if __name__ == "__main__":
    main()
