#!/usr/bin/env python3
"""Verify a CyberGuardian HMAC-signed audit checkpoint."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control-plane" / "api"))
from audit_ledger import LedgerIntegrityError, verify_signed_checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()
    raw_key = os.environ.get("CG_AUDIT_CHECKPOINT_KEY_HEX", "")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError:
        print("Checkpoint verification failed: invalid hexadecimal key", file=sys.stderr)
        return 2
    if len(key) < 32:
        print("Checkpoint verification failed: set CG_AUDIT_CHECKPOINT_KEY_HEX to at least 64 hex characters", file=sys.stderr)
        return 2
    try:
        result = verify_signed_checkpoint(args.snapshot, key)
    except (LedgerIntegrityError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Checkpoint verification failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
