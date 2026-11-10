#!/usr/bin/env python3
"""Provision, rotate, or revoke one CyberGuardian agent's credentials.

Run on the controller host. The generated secrets are printed once for secure
provisioning into that agent's local environment file. Never commit data/.
"""
from __future__ import annotations

import argparse
import re
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane" / "api"))
from agent_credentials import load_agent_credentials, write_agent_credentials


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


def _valid_identifier(value: str) -> bool:
    return bool(_IDENTIFIER.fullmatch(value))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument(
        "--tenant-id",
        default=None,
        help="tenant to bind; omitted rotations/re-enrollments preserve the existing tenant",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--rotate", action="store_true", help="replace existing active credentials")
    action.add_argument("--revoke", action="store_true", help="revoke existing credentials")
    args = parser.parse_args()

    asset_id = args.asset_id.strip()
    if not _valid_identifier(asset_id):
        parser.error("asset-id must be 1-128 characters: letters, digits, dot, underscore, colon or hyphen")

    agents = load_agent_credentials()
    current = agents.get(asset_id)
    if args.revoke:
        if not isinstance(current, dict):
            print("No credentials found for this asset.", file=sys.stderr)
            return 2
        current["status"] = "revoked"
        current["revoked_at"] = time.time()
        agents[asset_id] = current
        write_agent_credentials(agents)
        print(f"Revoked credentials for asset {asset_id}.")
        return 0

    if current and current.get("status", "active") == "active" and not args.rotate:
        print("Active credentials already exist. Use --rotate to replace them.", file=sys.stderr)
        return 2

    tenant_id = (
        args.tenant_id.strip()
        if args.tenant_id is not None
        else str((current or {}).get("tenant_id") or "default").strip()
    )
    if not _valid_identifier(tenant_id):
        parser.error("tenant-id must be 1-128 characters: letters, digits, dot, underscore, colon or hyphen")

    record = {
        "tenant_id": tenant_id,
        "api_key": "cg_agent_" + secrets.token_urlsafe(32),
        "identity_secret": secrets.token_urlsafe(48),
        "command_secret": secrets.token_urlsafe(48),
        "status": "active",
        "created_at": time.time(),
        "rotated_at": time.time() if args.rotate else None,
    }
    agents[asset_id] = record
    write_agent_credentials(agents)

    print("# Copy these values to this agent's protected environment file.")
    print(f"CYBERGUARDIAN_ASSET_ID={asset_id}")
    print(f"CYBERGUARDIAN_TENANT={tenant_id}")
    print(f"CYBERGUARDIAN_API_KEY={record['api_key']}")
    print(f"CG_AGENT_IDENTITY_SECRET={record['identity_secret']}")
    print(f"CG_COMMAND_SIGNING_SECRET={record['command_secret']}")
    print("CG_REQUIRE_COMMAND_SIG=1")
    print("CG_REQUIRE_AGENT_IDENTITY=1")
    print("Provision these secrets securely; do not paste them into GitHub or chat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
