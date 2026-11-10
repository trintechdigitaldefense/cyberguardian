#!/usr/bin/env python3
"""Verify the integrity of CyberGuardian's append-only audit ledger."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control-plane" / "api"))
from audit_ledger import verify_ledger


def main() -> int:
    default_path = Path(
        os.environ.get("CG_AUDIT_LEDGER_PATH")
        or (Path(os.environ.get("CG_DATA_DIR", str(ROOT / "data"))) / "audit_ledger.jsonl")
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=default_path)
    args = parser.parse_args()
    result = verify_ledger(args.path)
    print(json.dumps({"path": str(args.path), **result}, indent=2))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
