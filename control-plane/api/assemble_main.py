#!/usr/bin/env python3
"""Assemble main.py from main.py.part* (GitHub size workaround)."""
from pathlib import Path
here = Path(__file__).resolve().parent
parts = sorted(here.glob("main.py.part*"))
out = here / "main.py"
if not parts:
    print("no main.py.part* found — using existing main.py")
    raise SystemExit(0)
data = "".join(p.read_text() for p in parts)
if not out.exists() or out.read_text() != data:
    out.write_text(data)
    print("assembled main.py", len(data), "bytes from", [p.name for p in parts])
else:
    print("main.py already matches parts", len(data))
