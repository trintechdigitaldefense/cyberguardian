#!/usr/bin/env python3
"""Restore a verified CyberGuardian audit checkpoint to a separate ledger path."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _checkpoint_key_hex() -> str:
    raw = os.environ.get("CG_AUDIT_CHECKPOINT_KEY_HEX", "").strip()
    if raw:
        return raw
    data_dir = Path(os.environ.get("CG_DATA_DIR", str(ROOT / "data"))).expanduser()
    if not data_dir.is_absolute():
        data_dir = ROOT / data_dir
    credentials_path = data_dir / "credentials.json"
    try:
        payload = json.loads(credentials_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("set CG_AUDIT_CHECKPOINT_KEY_HEX or provision audit_checkpoint_key_hex in credentials.json") from exc
    if not isinstance(payload, dict):
        raise ValueError("credentials file has an invalid schema")
    return str(payload.get("audit_checkpoint_key_hex") or "").strip()


sys.path.insert(0, str(ROOT / "control-plane" / "api"))
from audit_ledger import LedgerIntegrityError, restore_signed_checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument(
        "--replace", action="store_true",
        help="explicitly allow replacing an existing destination ledger",
    )
    args = parser.parse_args()
    raw_key = _checkpoint_key_hex()
    try:
        key = bytes.fromhex(raw_key)
    except ValueError:
        print("Checkpoint restore refused: invalid hexadecimal key", file=sys.stderr)
        return 2
    if len(key) < 32:
        print("Checkpoint restore refused: set CG_AUDIT_CHECKPOINT_KEY_HEX to at least 64 hex characters", file=sys.stderr)
        return 2
    try:
        result = restore_signed_checkpoint(
            args.snapshot, args.destination, key, overwrite=args.replace
        )
    except (LedgerIntegrityError, OSError, ValueError) as exc:
        print(f"Checkpoint restore refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
