#!/usr/bin/env python3
"""Assemble main_full.py from gateway_z; verify SHA-256."""
from pathlib import Path
import base64, hashlib, sys, zlib

ROOT = Path(__file__).resolve().parent
EXPECTED_SHA = "09fb7d3bc9019aa4604a5b2d1b5df6f607b73d2e487332bddeebedf1547e9f80"
EXPECTED_SIZE = 57239

def try_gateway_z():
    parts = sorted((ROOT / "gateway_z").glob("*.txt"))
    if not parts:
        return None
    if len(parts) < 6:
        raise SystemExit(f"ERROR: gateway_z incomplete ({len(parts)} parts)")
    raw = base64.b64decode("".join(p.read_text().strip() for p in parts))
    return zlib.decompress(raw)

def verify(data: bytes) -> None:
    if b"CyberGuardian API Gateway" not in data[:400]:
        raise SystemExit("ERROR: not gateway content")
    actual = hashlib.sha256(data).hexdigest()
    if actual != EXPECTED_SHA:
        raise SystemExit(f"ERROR: integrity failed\n  expected: {EXPECTED_SHA}\n  actual:   {actual}")
    data.decode("utf-8")

out = ROOT / "main_full.py"
data = try_gateway_z()
if not data:
    raise SystemExit("ERROR: gateway_z missing")
verify(data)
out.write_bytes(data)
print(f"OK: wrote main_full.py ({len(data)} bytes) sha256={hashlib.sha256(data).hexdigest()}")
