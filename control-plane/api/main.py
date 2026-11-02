"""Bootstrap: assemble + load CyberGuardian API gateway."""
from __future__ import annotations
import importlib.util, subprocess, sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent
_FULL = _ROOT / "main_full.py"

def _ensure():
    asm = _ROOT / "assemble_main.py"
    r = subprocess.run([sys.executable, str(asm)], cwd=str(_ROOT), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr or r.stdout or "assemble failed")
    if not _FULL.exists() or _FULL.stat().st_size < 20000:
        raise RuntimeError("main_full.py missing")
    return _FULL

_target = _ensure()
_spec = importlib.util.spec_from_file_location("cg_api_main", _target)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["cg_api_main"] = _mod
_spec.loader.exec_module(_mod)
app = _mod.app
