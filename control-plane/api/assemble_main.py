#!/usr/bin/env python3
"""Assemble main_full.py from plain main_part*.py.txt. Fails if parts missing/corrupt."""
from pathlib import Path
ROOT = Path(__file__).resolve().parent
parts = sorted(ROOT.glob("main_part*.py.txt"))
if not parts:
    raise SystemExit("ERROR: no main_part*.py.txt — cannot assemble API gateway")
data = "".join(p.read_text(encoding="utf-8") for p in parts)
if "CyberGuardian API Gateway" not in data[:400]:
    raise SystemExit("ERROR: assembled content is not the API gateway")
if len(data) < 20000:
    raise SystemExit(f"ERROR: assembled size {len(data)} too small")
out = ROOT / "main_full.py"
out.write_text(data, encoding="utf-8")
print(f"OK: wrote {out} ({len(data)} bytes) from {len(parts)} parts")
