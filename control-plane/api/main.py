"""Bootstrap: assemble full gateway from main_part*.py.txt if needed, then load it."""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_FULL = _ROOT / "_assembled_main.py"
_PARTS = sorted(_ROOT.glob("main_part*.py.txt"))

def _assemble() -> Path:
    if not _PARTS:
        raise RuntimeError(
            "CyberGuardian API: main_part*.py.txt missing. "
            "Repository is incomplete — restore full gateway source."
        )
    data = "".join(p.read_text(encoding="utf-8") for p in _PARTS)
    if "CyberGuardian API Gateway" not in data[:400]:
        raise RuntimeError("Assembled main.py does not look like the gateway")
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
