"""CyberGuardian API Gateway — assembles from gateway_parts at import time."""
from pathlib import Path
import base64
import importlib.util
import sys
import zlib

_here = Path(__file__).resolve().parent
_parts_dir = _here / "gateway_parts"
_cache = _here / "_gateway_assembled.py"


def _load_parts() -> str:
    plain = sorted(p for p in _parts_dir.glob("part*.py") if not p.name.endswith(".z64"))
    if plain:
        return "".join(p.read_text() for p in plain)
    z64 = sorted(_parts_dir.glob("part*.py.z64"))
    if not z64:
        raise RuntimeError("missing gateway_parts/part*.py or part*.py.z64")
    out = []
    for p in z64:
        out.append(zlib.decompress(base64.b64decode(p.read_text().strip())).decode())
    return "".join(out)


def _ensure():
    data = _load_parts()
    if not _cache.exists() or _cache.read_text() != data:
        _cache.write_text(data)
    return data


_ensure()
spec = importlib.util.spec_from_file_location("cyberguardian_gateway", _cache)
mod = importlib.util.module_from_spec(spec)
sys.modules["cyberguardian_gateway"] = mod
spec.loader.exec_module(mod)
app = mod.app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
