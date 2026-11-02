"""Bootstrap: assemble + load CyberGuardian API gateway (canonical)."""
from __future__ import annotations
import importlib.util, subprocess, sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_FULL = _ROOT / "main_full.py"

def _ensure_full() -> Path:
    asm = _ROOT / "assemble_main.py"
    if asm.exists():
        r = subprocess.run([sys.executable, str(asm)], cwd=str(_ROOT), capture_output=True, text=True)
        if r.returncode != 0:
            if _FULL.exists() and _FULL.stat().st_size > 20000:
                return _FULL
            raise RuntimeError(r.stderr or r.stdout or "assemble failed")
    if not _FULL.exists() or _FULL.stat().st_size < 20000:
        raise RuntimeError("main_full.py missing after assemble")
    return _FULL

_target = _ensure_full()
_spec = importlib.util.spec_from_file_location("cg_api_main", _target)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"Cannot load {_target}")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["cg_api_main"] = _mod
_spec.loader.exec_module(_mod)
app = _mod.app
