#!/usr/bin/env python3
"""Decode gateway_z/*.txt (zlib+base64) -> main_full.py. Intact single source."""
from pathlib import Path
import base64, zlib, hashlib, sys
ROOT = Path(__file__).resolve().parent
parts = sorted((ROOT / "gateway_z").glob("*.txt"))
if not parts:
    raise SystemExit("ERROR: no gateway_z/*.txt")
raw = base64.b64decode("".join(p.read_text().strip() for p in parts))
data = zlib.decompress(raw)
if b"CyberGuardian API Gateway" not in data[:400]:
    raise SystemExit("ERROR: decoded content invalid")
if len(data) < 20000:
    raise SystemExit(f"ERROR: size {len(data)} too small")
out = ROOT / "main_full.py"
out.write_bytes(data)
print(f"OK: {out} ({len(data)} bytes) sha256={hashlib.sha256(data).hexdigest()}")
