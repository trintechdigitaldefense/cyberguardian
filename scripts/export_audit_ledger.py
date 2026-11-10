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
from audit_ledger import LedgerIntegrityError, export_signed_checkpoint


def main() -> int:
    data_dir = Path(os.environ.get("CG_DATA_DIR", str(ROOT / "data")))
    source = Path(os.environ.get("CG_AUDIT_LEDGER_PATH") or data_dir / "audit_ledger.jsonl")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=source)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--unsigned", action="store_true", help="export an unsigned snapshot (not suitable as an independent checkpoint)")
    args = parser.parse_args()
    try:
        if args.unsigned:
            from audit_ledger import export_verified_ledger
            manifest = export_verified_ledger(args.source, args.out)
        else:
            raw_key = os.environ.get("CG_AUDIT_CHECKPOINT_KEY_HEX", "")
            try:
                key = bytes.fromhex(raw_key)
            except ValueError as exc:
                raise ValueError("CG_AUDIT_CHECKPOINT_KEY_HEX must be valid hexadecimal") from exc
            if len(key) < 32:
                raise ValueError("set CG_AUDIT_CHECKPOINT_KEY_HEX to at least 64 hex characters (32 random bytes)")
            manifest = export_signed_checkpoint(args.source, args.out, key)
    except (LedgerIntegrityError, OSError, ValueError) as exc:
        print(f"Audit export refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
