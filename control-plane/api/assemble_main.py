#!/usr/bin/env python3
"""Assemble main_full.py from gateway_hex (hex-encoded zlib)."""
from pathlib import Path
import hashlib, sys, zlib

ROOT = Path(__file__).resolve().parent
EXPECTED_SHA = "39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674"

parts = sorted((ROOT / "gateway_hex").glob("*.hex"))
if not parts:
    raise SystemExit("ERROR: gateway_hex/*.hex missing")
raw = bytes.fromhex("".join(p.read_text().strip() for p in parts))
data = zlib.decompress(raw)
if b"CyberGuardian API Gateway" not in data[:400]:
    raise SystemExit("ERROR: not gateway content")
actual = hashlib.sha256(data).hexdigest()
if actual != EXPECTED_SHA:
    raise SystemExit(f"ERROR: sha mismatch\n  expected {EXPECTED_SHA}\n  actual   {actual}")
(ROOT / "main_full.py").write_bytes(data)
print(f"OK: main_full.py ({len(data)} bytes) sha256={actual}")
