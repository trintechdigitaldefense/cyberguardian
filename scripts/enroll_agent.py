#!/usr/bin/env python3
"""Provision, rotate, or revoke one CyberGuardian agent's credentials.

Run on the controller host. Secrets are stored in the protected controller registry and are never printed.
Use scripts/run_enrolled_agent.py to start a device directly from that registry.
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import shlex
import stat
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane" / "api"))
from agent_credentials import load_agent_credentials, write_agent_credentials


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


def _valid_identifier(value: str) -> bool:
    return bool(_IDENTIFIER.fullmatch(value))


def _validate_api_url(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(ch in value for ch in "\r\n\t")
    ):
        raise ValueError("api-url must be an absolute HTTP(S) URL without credentials, query or fragment")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("non-loopback agent API URLs must use HTTPS")
    return value.rstrip("/")


def _write_env_file(path: Path, values: dict[str, str]) -> None:
    path = path.expanduser()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not stat.S_ISDIR(parent.stat().st_mode) or (stat.S_IMODE(parent.stat().st_mode) & 0o077):
        raise RuntimeError("agent environment directory must have no group/other permissions (0700)")
    if path.exists() and path.is_dir():
        raise RuntimeError("agent environment path is a directory")
    payload = "".join(f"{key}={shlex.quote(value)}\n" for key, value in values.items())
    fd, temporary = tempfile.mkstemp(prefix=".agent.env.", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        dir_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            if os.path.exists(temporary):
                os.unlink(temporary)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument(
        "--tenant-id",
        default=None,
        help="tenant to bind; omitted rotations/re-enrollments preserve the existing tenant",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="write secrets to a protected agent environment file instead of printing them",
    )
    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:8080",
        help="controller URL for the agent (non-loopback URLs must use HTTPS)",
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

    tenant_id = (
        args.tenant_id.strip()
        if args.tenant_id is not None
        else str((current or {}).get("tenant_id") or "default").strip()
    )
    if not _valid_identifier(tenant_id):
        parser.error("tenant-id must be 1-128 characters: letters, digits, dot, underscore, colon or hyphen")
    try:
        api_url = _validate_api_url(args.api_url)
    except ValueError as exc:
        parser.error(str(exc))

    record = {
        "tenant_id": tenant_id,
        "api_key": "cg_agent_" + secrets.token_urlsafe(32),
        "identity_secret": secrets.token_urlsafe(48),
        "command_secret": secrets.token_urlsafe(48),
        "status": "active",
        "created_at": time.time(),
        "rotated_at": time.time() if args.rotate else None,
    }
    if current and current.get("status", "active") == "active" and not args.rotate:
        print("Active credentials already exist. Use --rotate to replace them.", file=sys.stderr)
        return 2

    env_values = {
        "CYBERGUARDIAN_API": api_url,
        "CYBERGUARDIAN_ASSET_ID": asset_id,
        "CYBERGUARDIAN_TENANT": tenant_id,
        "CYBERGUARDIAN_API_KEY": record["api_key"],
        "CG_AGENT_IDENTITY_SECRET": record["identity_secret"],
        "CG_COMMAND_SIGNING_SECRET": record["command_secret"],
        "CG_REQUIRE_AGENT_IDENTITY": "1",
        "CG_REQUIRE_COMMAND_SIG": "1",
    }
    if args.env_file:
        try:
            target = args.env_file.expanduser()
            # Validate the destination before committing the new active credentials.
            parent = target.parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if stat.S_IMODE(parent.stat().st_mode) & 0o077:
                raise RuntimeError("agent environment directory must have no group/other permissions (0700)")
        except (OSError, RuntimeError) as exc:
            parser.error(f"cannot prepare agent environment file: {exc}")

    agents[asset_id] = record
    write_agent_credentials(agents)

    if args.env_file:
        try:
            _write_env_file(args.env_file, env_values)
        except (OSError, RuntimeError) as exc:
            # Revoke the just-issued credentials rather than leave an active
            # enrollment with no safely provisioned destination.
            record["status"] = "revoked"
            record["revoked_at"] = time.time()
            agents[asset_id] = record
            write_agent_credentials(agents)
            parser.error(f"environment file write failed; enrollment was revoked: {exc}")
        print(f"Enrolled {asset_id} for tenant {tenant_id}; protected environment file written to {args.env_file}.")
        print("The file contains secrets. Do not print, paste, or commit it.")
        return 0

    print(f"Enrolled {asset_id} for tenant {tenant_id}; per-device credentials are stored in the protected controller registry.")
    print(f"Start this device with: CG_AGENT_ASSET_ID={asset_id} python3 scripts/run_enrolled_agent.py --asset-id {asset_id}")
    print("No secret values were displayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
