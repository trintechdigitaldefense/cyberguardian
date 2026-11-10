#!/usr/bin/env python3
"""Install control-plane/api/main_full.py from scripts/gwhex/*.hex"""
from pathlib import Path
import hashlib, zlib, sys
EXPECTED = "39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674"
def main():
    root = Path(__file__).resolve().parents[1]
    parts_dir = Path(__file__).resolve().parent / "gwhex"
    parts = sorted(parts_dir.glob("*.hex"))
    if not parts:
        single = Path(__file__).resolve().parent / "gateway.hex"
        if not single.exists():
            raise SystemExit("missing scripts/gwhex/*.hex")
        hx = single.read_text().strip()
    else:
        hx = "".join(p.read_text().strip() for p in parts)
    data = zlib.decompress(bytes.fromhex(hx))
    actual = hashlib.sha256(data).hexdigest()
    if actual != EXPECTED:
        raise SystemExit(f"sha mismatch: {actual}")
    if b"CyberGuardian API Gateway" not in data[:400]:
        raise SystemExit("not gateway")
    api = root / "control-plane" / "api"
    api.mkdir(parents=True, exist_ok=True)
    (api / "main_full.py").write_bytes(data)
    (api / "main.py").write_text(
        "from pathlib import Path\nimport importlib.util, sys\n"
        "p = Path(__file__).resolve().parent / 'main_full.py'\n"
        "s = importlib.util.spec_from_file_location('cg_api_main', p)\n"
        "m = importlib.util.module_from_spec(s); sys.modules['cg_api_main']=m; s.loader.exec_module(m)\n"
        "app = m.app\n"
    )
    print(f"OK: main_full.py ({len(data)} bytes) sha256={actual}")
if __name__ == "__main__":
    main()
