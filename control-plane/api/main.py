"""Bootstrap: assemble full gateway from gw_src_*.txt / main_part*.py.txt, then load app."""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_FULL = _ROOT / "_assembled_main.py"

def _parts():
    p = sorted(_ROOT.glob("gw_src_*.txt"))
    if not p:
        p = sorted(_ROOT.glob("main_part*.py.txt"))
    return p

def _assemble() -> Path:
    parts = _parts()
    if not parts:
        raise RuntimeError(
            "CyberGuardian API: gw_src_*.txt / main_part*.py.txt missing. "
            "Repository incomplete — push gateway source fragments."
        )
    data = "".join(p.read_text(encoding="utf-8") for p in parts)
    if "CyberGuardian API Gateway" not in data[:400]:
        raise RuntimeError("Assembled main does not look like the gateway")
    if len(data) < 20000:
        raise RuntimeError(f"Assembled size {len(data)} too small")
    _FULL.write_text(data, encoding="utf-8")
    return _FULL

_full_src = _ROOT / "main_full.py"
if _full_src.exists() and _full_src.stat().st_size > 20000:
    target = _full_src
else:
    target = _assemble()

_spec = importlib.util.spec_from_file_location("cg_api_main", target)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"Cannot load {target}")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["cg_api_main"] = _mod
_spec.loader.exec_module(_mod)
app = _mod.app
