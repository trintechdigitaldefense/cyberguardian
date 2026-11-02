#!/usr/bin/env python3
"""Assemble main_full.py. Prefers gateway_z (zlib+b64), then gateway_b64, then gw_src_*.txt."""
from pathlib import Path
import base64
import hashlib
import sys
import zlib

ROOT = Path(__file__).resolve().parent

def try_gateway_z():
    parts = sorted((ROOT / "gateway_z").glob("*.txt"))
    if not parts:
        return None
    raw = base64.b64decode("".join(p.read_text().strip() for p in parts))
    return zlib.decompress(raw)

def try_gateway_b64():
    parts = sorted((ROOT / "gateway_b64").glob("p*.b64"))
    if not parts:
        return None
    return base64.b64decode("".join(p.read_text().strip() for p in parts))

def try_txt():
    parts = sorted(ROOT.glob("gw_src_*.txt"))
    if not parts:
        parts = sorted(ROOT.glob("main_part*.py.txt"))
    if not parts:
        return None
    return "".join(p.read_text(encoding="utf-8") for p in parts).encode("utf-8")

existing = ROOT / "main_full.py"
if existing.exists() and existing.stat().st_size > 20000:
    text = existing.read_text(encoding="utf-8", errors="replace")
    if "CyberGuardian API Gateway" in text[:400]:
        print(f"OK: main_full.py already present ({existing.stat().st_size} bytes)")
        sys.exit(0)

for name, fn in (("gateway_z", try_gateway_z), ("gateway_b64", try_gateway_b64), ("text parts", try_txt)):
    try:
        data = fn()
    except Exception as e:
        print(f"skip {name}: {e}")
        continue
    if not data:
        continue
    if isinstance(data, str):
        data = data.encode("utf-8")
    if b"CyberGuardian API Gateway" not in data[:400]:
        print(f"skip {name}: not gateway content")
        continue
    if len(data) < 20000:
        print(f"skip {name}: too small ({len(data)})")
        continue
    existing.write_bytes(data)
    print(f"OK: wrote main_full.py from {name} ({len(data)} bytes) sha256={hashlib.sha256(data).hexdigest()}")
    sys.exit(0)

raise SystemExit("ERROR: no gateway_z / gateway_b64 / gw_src_*.txt — cannot assemble API gateway")
