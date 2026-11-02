#!/usr/bin/env python3
"""Decode gateway_b64/p*.b64 -> main_full.py. Run from control-plane/api/"""
from pathlib import Path
import base64, hashlib
ROOT = Path(__file__).resolve().parent
parts = sorted((ROOT / "gateway_b64").glob("p*.b64"))
if not parts:
    raise SystemExit("no gateway_b64/p*.b64")
data = base64.b64decode("".join(p.read_text().strip() for p in parts))
if b"CyberGuardian API Gateway" not in data[:400]:
    raise SystemExit("decoded content invalid")
(ROOT / "main_full.py").write_bytes(data)
print("OK main_full.py", len(data), hashlib.sha256(data).hexdigest())
