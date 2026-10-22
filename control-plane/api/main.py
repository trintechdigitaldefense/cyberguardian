"""CyberGuardian API Gateway — assembles from gateway_parts at import time."""
from pathlib import Path
import sys

_here = Path(__file__).resolve().parent
_parts_dir = _here / "gateway_parts"
_cache = _here / "_gateway_assembled.py"

def _ensure():
    parts = sorted(_parts_dir.glob("part*.py"))
    if not parts:
        raise RuntimeError("missing gateway_parts/part*.py — clone incomplete")
    data = "".join(p.read_text() for p in parts)
    if not _cache.exists() or _cache.read_text() != data:
        _cache.write_text(data)
    return data

_ensure()
import importlib.util
spec = importlib.util.spec_from_file_location("cyberguardian_gateway", _cache)
mod = importlib.util.module_from_spec(spec)
sys.modules["cyberguardian_gateway"] = mod
spec.loader.exec_module(mod)
app = mod.app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
