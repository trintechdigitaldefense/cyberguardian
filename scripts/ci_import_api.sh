#!/usr/bin/env bash
# CI: fresh-tree import test for API gateway
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/control-plane/api"
python3 assemble_main.py
python3 -c "
import importlib.util
from pathlib import Path
p = Path('main_full.py')
assert p.stat().st_size > 20000
spec = importlib.util.spec_from_file_location('cg', p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert hasattr(mod, 'app')
print('OK: API gateway imports, size', p.stat().st_size)
"
