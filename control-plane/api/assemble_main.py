#!/usr/bin/env python3
"""Assemble main_full.py from gateway_b64 or gw_src_*.txt. Fails if missing."""
from pathlib import Path
import base64
import hashlib
import sys

ROOT = Path(__file__).resolve().parent

def from_b64():
    parts = sorted((ROOT / "gateway_b64").glob("p*.b64"))
    if not parts:
        return None
    return base64.b64decode("".join(p.read_text().strip() for p in parts))

def from_txt():
    parts = sorted(ROOT.glob("gw_src_*.txt"))
    if not parts:
        parts = sorted(ROOT.glob("main_part*.py.txt"))
    if not parts:
        return None
    return "".join(p.read_text(encoding="utf-8") for p in parts)

existing = ROOT / "main_full.py"
if existing.exists() and existing.stat().st_size > 20000:
    text = existing.read_text(encoding="utf-8", errors="replace")
    if "CyberGuardian API Gateway" in text[:400]:
        print(f"OK: main_full.py already present ({existing.stat().st_size} bytes)")
        sys.exit(0)

raw = from_b64()
if raw:
    if b"CyberGuardian API Gateway" not in raw[:400]:
        raise SystemExit("ERROR: b64 decode is not the API gateway")
    (ROOT / "main_full.py").write_bytes(raw)
    print(f"OK: wrote main_full.py from gateway_b64 ({len(raw)} bytes) sha256={hashlib.sha256(raw).hexdigest()}")
    sys.exit(0)

text = from_txt()
if text:
    if "CyberGuardian API Gateway" not in text[:400]:
        raise SystemExit("ERROR: assembled text is not the API gateway")
    if len(text) < 20000:
        raise SystemExit(f"ERROR: assembled size {len(text)} too small")
    (ROOT / "main_full.py").write_text(text, encoding="utf-8")
    print(f"OK: wrote main_full.py from text parts ({len(text)} bytes)")
    sys.exit(0)

raise SystemExit("ERROR: no gateway_b64/p*.b64 or gw_src_*.txt — cannot assemble API gateway")
