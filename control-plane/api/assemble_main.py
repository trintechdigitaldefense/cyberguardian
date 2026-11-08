#!/usr/bin/env python3
"""Build the API gateway from the complete, versioned gateway_z source set.

The gateway_z/*.txt files are base64-encoded zlib chunks. This is the canonical
source set for the current R2 branch; gateway_hex is a stale/partial artifact
and must not be used by release builds.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import re
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PARTS_DIR = ROOT / "gateway_z"
CHECKSUM_FILE = ROOT / "GATEWAY_SHA256.txt"
OUTPUT = ROOT / "main_full.py"


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def main() -> None:
    parts = sorted(PARTS_DIR.glob("[0-9][0-9].txt"))
    if len(parts) != 6:
        fail(f"expected exactly six gateway_z chunks (00.txt-05.txt), found {len(parts)}")

    expected_names = [f"{i:02d}.txt" for i in range(6)]
    actual_names = [p.name for p in parts]
    if actual_names != expected_names:
        fail(f"gateway_z chunks incomplete or out of order: {actual_names}")

    try:
        encoded = "".join(p.read_text(encoding="ascii").strip() for p in parts)
        compressed = base64.b64decode(encoded, validate=True)
        source = zlib.decompress(compressed)
        source_text = source.decode("utf-8")
    except (OSError, UnicodeError, ValueError, zlib.error) as exc:
        fail(f"gateway source decoding failed: {exc}")

    if len(source) < 20_000 or b"CyberGuardian API Gateway" not in source[:400]:
        fail(f"decoded gateway source failed structural checks (size={len(source)})")

    try:
        ast.parse(source_text, filename="main_full.py")
    except SyntaxError as exc:
        fail(f"decoded gateway source is not valid Python: {exc}")

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
        fail(f"gateway SHA-256 mismatch: expected {expected_sha}, got {actual_sha}")

    size_match = re.search(r"^#\s*size\s+(\d+)\s*$", checksum_text, re.MULTILINE)
    if size_match and len(source) != int(size_match.group(1)):
        fail(f"gateway size mismatch: expected {size_match.group(1)}, got {len(source)}")

    temporary = OUTPUT.with_suffix(".py.tmp")
    temporary.write_bytes(source)
    temporary.replace(OUTPUT)
    print(f"OK: {OUTPUT.name} ({len(source)} bytes) sha256={actual_sha}")


if __name__ == "__main__":
    main()
