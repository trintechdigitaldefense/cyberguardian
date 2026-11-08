"""Portable runtime paths for repository and container deployments."""
from __future__ import annotations

import os
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
_MODULE_FILE = Path(__file__).resolve()
REPO_ROOT = _MODULE_FILE.parents[2] if len(_MODULE_FILE.parents) > 2 else MODULE_DIR
DATA_DIR = Path(os.environ.get("CG_DATA_DIR", str(REPO_ROOT / "data"))).expanduser()
CONFIG_DIR = Path(os.environ.get("CG_CONFIG_DIR", str(REPO_ROOT / "configs"))).expanduser()
