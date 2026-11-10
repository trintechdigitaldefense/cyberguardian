#!/usr/bin/env python3
"""Provision a tenant-scoped dashboard user without exposing passwords in argv."""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))

from user_admin import upsert_user


def main() -> int:
    parser = argparse.ArgumentParser(description="Add or rotate a CyberGuardian dashboard user")
    parser.add_argument("--username", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--role", required=True, choices=("admin", "operator", "analyst", "viewer"))
    parser.add_argument("--replace", action="store_true", help="replace an existing user's password/role/tenant")
    args = parser.parse_args()

    password = getpass.getpass("New dashboard password (10+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        parser.error("password confirmation does not match")
    try:
        user = upsert_user(
            username=args.username,
            tenant_id=args.tenant_id,
            role=args.role,
            password=password,
            replace=args.replace,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(
        f"{'Updated' if args.replace else 'Provisioned'} user {user['username']} "
        f"for tenant {user['tenant_id']} with role {user['role']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
