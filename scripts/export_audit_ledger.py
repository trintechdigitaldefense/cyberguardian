#!/usr/bin/env python3
"""Export a verified, consistent CyberGuardian audit ledger snapshot."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control-plane" / "api"))
from audit_ledger import LedgerIntegrityError, export_verified_ledger


def main() -> int:
    data_dir = Path(os.environ.get("CG_DATA_DIR", str(ROOT / "data")))
    source = Path(os.environ.get("CG_AUDIT_LEDGER_PATH") or data_dir / "audit_ledger.jsonl")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=source)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = export_verified_ledger(args.source, args.out)
    except (LedgerIntegrityError, OSError, ValueError) as exc:
        print(f"Audit export refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
