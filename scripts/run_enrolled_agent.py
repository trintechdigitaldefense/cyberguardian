#!/usr/bin/env python3
"""Launch one enrolled CyberGuardian agent without printing device secrets."""
from __future__ import annotations

import argparse
import os
import shlex
import stat
import sys
from pathlib import Path
from typing import Mapping, Optional
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "control-plane" / "api"
AGENT_SCRIPT = ROOT / "agents" / "linux-ebpf" / "agent.py"
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

import agent_credentials  # noqa: E402

SAFE_AGENT_ENV_KEYS = {
    "PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "PYTHONPATH", "VIRTUAL_ENV",
    "CG_DATA_DIR", "CG_HARDENED", "CG_PRODUCTION", "CG_AGENT_REPLAY_DB",
    "CG_OFFLINE_QUEUE_PATH", "CG_AGENT_QUEUE_MAX_ITEMS", "CG_AGENT_QUEUE_MAX_BYTES",
    "CG_AGENT_INTERVAL", "CG_SCAN_INTERVAL", "CYBERGUARDIAN_SCAN_INTERVAL",
    "CYBERGUARDIAN_TAGS", "CYBERGUARDIAN_LOG_LEVEL", "SSL_CERT_FILE", "SSL_CERT_DIR",
}


def read_agent_environment_file(path: str) -> dict[str, str]:
    env_file = Path(path).expanduser()
    if env_file.is_symlink() or not env_file.is_file():
        raise PermissionError("agent environment file must be a regular, non-symlink file")
    if stat.S_IMODE(env_file.stat().st_mode) & 0o077:
        raise PermissionError("agent environment file must be private (0600)")
    if env_file.parent.is_symlink() or stat.S_IMODE(env_file.parent.stat().st_mode) & 0o077:
        raise PermissionError("agent environment directory must be private (0700)")
    allowed = {
        "CYBERGUARDIAN_API", "CYBERGUARDIAN_ASSET_ID", "CYBERGUARDIAN_TENANT",
        "CYBERGUARDIAN_API_KEY", "CG_AGENT_IDENTITY_SECRET",
        "CG_COMMAND_SIGNING_SECRET", "CG_REQUIRE_AGENT_IDENTITY", "CG_REQUIRE_COMMAND_SIG",
    }
    selected: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator or name not in allowed:
            continue
        if name in selected:
            raise ValueError(f"agent environment file repeats {name}")
        parts = shlex.split(value, comments=True, posix=True)
        if parts:
            selected[name] = parts[0]
    required = (
        "CYBERGUARDIAN_ASSET_ID", "CYBERGUARDIAN_TENANT", "CYBERGUARDIAN_API_KEY",
        "CG_AGENT_IDENTITY_SECRET", "CG_COMMAND_SIGNING_SECRET",
    )
    if any(not selected.get(name, "").strip() for name in required):
        raise ValueError("agent environment file is missing required per-device credentials")
    if selected.get("CG_REQUIRE_AGENT_IDENTITY") != "1" or selected.get("CG_REQUIRE_COMMAND_SIG") != "1":
        raise ValueError("agent environment file must require identity and command signatures")
    return selected

def _validate_api_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(ch in str(value) for ch in "\r\n\t")
    ):
        raise ValueError("controller URL must be absolute HTTP(S) without credentials, query or fragment")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("non-loopback controller URLs must use HTTPS")
    return str(value).strip().rstrip("/")


def build_agent_environment(
    asset_id: str,
    *,
    base_env: Optional[Mapping[str, str]] = None,
    api_url: Optional[str] = None,
    credential_record: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    asset_id = str(asset_id or "").strip()
    if not asset_id:
        raise ValueError("asset ID is required")
    record = dict(credential_record) if credential_record is not None else agent_credentials.get_agent_credential(asset_id)
    if not isinstance(record, dict):
        raise PermissionError("agent is not enrolled or its credentials have been revoked")
    if credential_record is not None and str(record.get("status") or "active") != "active":
        raise PermissionError("agent environment file enrollment is not active")

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

    source_env = os.environ if base_env is None else base_env
    env = {key: str(value) for key, value in source_env.items() if key in SAFE_AGENT_ENV_KEYS}
    controller = str(api_url or source_env.get("CYBERGUARDIAN_API") or source_env.get("CG_CONTROLLER_URL") or "http://127.0.0.1:8080").strip()
    controller = _validate_api_url(controller)

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
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--asset-id", help="Enrolled asset ID from the controller registry")
    source.add_argument("--env-file", help="Private environment file; only its asset ID and API URL are read")
    parser.add_argument("--api", default=None, help="Controller API URL (defaults to CYBERGUARDIAN_API)")
    parser.add_argument("--interval", type=int, default=60, help="Agent scan interval in seconds")
    args = parser.parse_args()
    if args.interval < 5:
        parser.error("--interval must be at least 5 seconds")
    try:
        asset_id = args.asset_id
        file_values = None
        if args.env_file:
            file_values = read_agent_environment_file(args.env_file)
            asset_id = file_values["CYBERGUARDIAN_ASSET_ID"]
            file_record = {
                "tenant_id": file_values["CYBERGUARDIAN_TENANT"],
                "api_key": file_values["CYBERGUARDIAN_API_KEY"],
                "identity_secret": file_values["CG_AGENT_IDENTITY_SECRET"],
                "command_secret": file_values["CG_COMMAND_SIGNING_SECRET"],
                "status": "active",
            }
            env = build_agent_environment(
                asset_id,
                api_url=args.api or file_values.get("CYBERGUARDIAN_API"),
                credential_record=file_record,
            )
        else:
            env = build_agent_environment(asset_id, api_url=args.api)
    except (PermissionError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    if not AGENT_SCRIPT.is_file():
        parser.error(f"agent entrypoint is missing: {AGENT_SCRIPT}")

    argv = [sys.executable, str(AGENT_SCRIPT), "--interval", str(args.interval)]
    print(f"Starting enrolled agent {env['CYBERGUARDIAN_ASSET_ID']} for tenant {env['CYBERGUARDIAN_TENANT']}; server credentials are excluded and device secrets are not displayed.")
    os.execvpe(sys.executable, argv, env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
