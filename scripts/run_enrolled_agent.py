#!/usr/bin/env python3
"""Launch one enrolled CyberGuardian agent without printing device secrets."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Mapping, Optional

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "control-plane" / "api"
AGENT_SCRIPT = ROOT / "agents" / "linux-ebpf" / "agent.py"
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

import agent_credentials  # noqa: E402


def build_agent_environment(
    asset_id: str,
    *,
    base_env: Optional[Mapping[str, str]] = None,
    api_url: Optional[str] = None,
) -> dict[str, str]:
    asset_id = str(asset_id or "").strip()
    if not asset_id:
        raise ValueError("asset ID is required")
    record = agent_credentials.get_agent_credential(asset_id)
    if not isinstance(record, dict):
        raise PermissionError("agent is not enrolled or its credentials have been revoked")

    tenant_id = str(record.get("tenant_id") or "").strip()
    api_key = str(record.get("api_key") or "").strip()
    identity_secret = str(record.get("identity_secret") or "").strip()
    command_secret = str(record.get("command_secret") or "").strip()
    if (
        not tenant_id
        or len(api_key.encode("utf-8")) < 32
        or len(identity_secret.encode("utf-8")) < 32
        or len(command_secret.encode("utf-8")) < 32
    ):
        raise PermissionError("enrollment record is incomplete; refusing to start the agent")

    env = dict(base_env or os.environ)
    controller = str(api_url or env.get("CYBERGUARDIAN_API") or env.get("CG_CONTROLLER_URL") or "http://127.0.0.1:8080").strip()
    if not controller.startswith(("http://", "https://")):
        raise ValueError("controller URL must use http:// or https://")

    env.update({
        "CYBERGUARDIAN_API": controller,
        "CG_CONTROLLER_URL": controller,
        "CYBERGUARDIAN_API_KEY": api_key,
        "CYBERGUARDIAN_ASSET_ID": asset_id,
        "CYBERGUARDIAN_TENANT": tenant_id,
        "CG_AGENT_IDENTITY_SECRET": identity_secret,
        "CG_COMMAND_SIGNING_SECRET": command_secret,
        "CG_REQUIRE_AGENT_IDENTITY": "1",
        "CG_REQUIRE_COMMAND_SIG": "1",
    })
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-id", required=True, help="Enrolled asset ID from the controller registry")
    parser.add_argument("--api", default=None, help="Controller API URL (defaults to CYBERGUARDIAN_API)")
    parser.add_argument("--interval", type=int, default=60, help="Agent scan interval in seconds")
    args = parser.parse_args()
    if args.interval < 5:
        parser.error("--interval must be at least 5 seconds")
    try:
        env = build_agent_environment(args.asset_id, api_url=args.api)
    except (PermissionError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    if not AGENT_SCRIPT.is_file():
        parser.error(f"agent entrypoint is missing: {AGENT_SCRIPT}")

    argv = [sys.executable, str(AGENT_SCRIPT), "--interval", str(args.interval)]
    print(f"Starting enrolled agent {args.asset_id} for tenant {env['CYBERGUARDIAN_TENANT']}; secrets are not displayed.")
    os.execvpe(sys.executable, argv, env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
