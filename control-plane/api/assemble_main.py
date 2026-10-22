#!/usr/bin/env python3
"""Assemble main.py from parts if present (GitHub size workaround)."""
from pathlib import Path

here = Path(__file__).resolve().parent
parts = sorted(here.glob("main.py.part*"))
out = here / "main.py"
if parts:
    data = "\n".join(p.read_text() for p in parts)
    # Always rebuild when parts exist so clone matches source of truth
    if not out.exists() or out.stat().st_size != len(data) or "1.4.0-tier3" not in out.read_text()[:500]:
        out.write_text(data)
        print("assembled main.py", len(data), "bytes from", [p.name for p in parts])
    else:
        print("main.py already current", out.stat().st_size)
else:
    print("no main.py.part* found — using existing main.py")
