#!/usr/bin/env python3
"""Tenant-scoped issue-memory archive export and restore operations."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control-plane" / "api"))

import issue_memory


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export or restore one tenant's archived CyberGuardian issue history."
    )
    commands = parser.add_subparsers(dest="operation", required=True)

    export_parser = commands.add_parser("export", help="write a private tenant-only archive snapshot")
    export_parser.add_argument("--tenant-id", required=True)
    export_parser.add_argument("--out", required=True, type=Path)

    restore_parser = commands.add_parser("restore", help="merge a tenant-only archive snapshot")
    restore_parser.add_argument("--tenant-id", required=True)
    restore_parser.add_argument("--input", required=True, type=Path)

    args = parser.parse_args()
    try:
        if args.operation == "export":
            result = issue_memory.export_archived_issues(args.out, args.tenant_id)
        else:
            result = issue_memory.restore_archived_issues(args.input, args.tenant_id)
    except Exception as exc:
        print(f"Issue archive operation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
