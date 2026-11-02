#!/usr/bin/env python3
"""Assemble main_full.py — prefer gateway_hex (safe alphabet), then gateway_z."""
from pathlib import Path
import base64, hashlib, sys, zlib

ROOT = Path(__file__).resolve().parent
EXPECTED_SHA = "09fb7d3bc9019aa4604a5b2d1b5df6f607b73d2e487332bddeebedf1547e9f80"

def from_hex():
    parts = sorted((ROOT / "gateway_hex").glob("*.hex"))
    if not parts:
        return None
    return zlib.decompress(bytes.fromhex("".join(p.read_text().strip() for p in parts)))

def from_z():
    parts = sorted((ROOT / "gateway_z").glob("*.txt"))
    if not parts:
        return None
    return zlib.decompress(base64.b64decode("".join(p.read_text().strip() for p in parts)))

def verify(data: bytes):
    if b"CyberGuardian API Gateway" not in data[:400]:
        raise SystemExit("ERROR: not gateway")
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise SystemExit(f"ERROR: sha mismatch {hashlib.sha256(data).hexdigest()}")

for name, fn in (("gateway_hex", from_hex), ("gateway_z", from_z)):
    try:
        data = fn()
    except Exception as e:
        print("skip", name, e)
        continue
    if not data:
        continue
    verify(data)
    (ROOT / "main_full.py").write_bytes(data)
    print(f"OK: {name} {len(data)} bytes")
    sys.exit(0)
raise SystemExit("ERROR: no valid gateway source")
