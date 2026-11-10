from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "cg_run_enrolled_agent_test", ROOT / "scripts" / "run_enrolled_agent.py"
)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def test_enrolled_agent_launcher_uses_device_scoped_secrets_without_leaking(monkeypatch):
    record = {
        "tenant_id": "tenant-a",
        "api_key": "agent-api-key-" + "a" * 40,
        "identity_secret": "identity-secret-" + "b" * 40,
        "command_secret": "command-secret-" + "c" * 40,
        "status": "active",
    }
    monkeypatch.setattr(launcher.agent_credentials, "get_agent_credential", lambda asset_id: record if asset_id == "asset-a" else None)
    env = launcher.build_agent_environment(
        "asset-a",
        base_env={"PATH": "/usr/bin", "CG_DATA_DIR": "/secure/cg-data"},
        api_url="https://controller.example",
    )
    assert env["CYBERGUARDIAN_API"] == "https://controller.example"
    assert env["CYBERGUARDIAN_API_KEY"] == record["api_key"]
    assert env["CYBERGUARDIAN_ASSET_ID"] == "asset-a"
    assert env["CYBERGUARDIAN_TENANT"] == "tenant-a"
    assert env["CG_AGENT_IDENTITY_SECRET"] == record["identity_secret"]
    assert env["CG_COMMAND_SIGNING_SECRET"] == record["command_secret"]
    assert env["CG_REQUIRE_AGENT_IDENTITY"] == "1"
    assert env["CG_REQUIRE_COMMAND_SIG"] == "1"
    assert env["CG_DATA_DIR"] == "/secure/cg-data"


def test_enrolled_agent_launcher_refuses_revoked_or_unknown_device(monkeypatch):
    monkeypatch.setattr(launcher.agent_credentials, "get_agent_credential", lambda _asset_id: None)
    try:
        launcher.build_agent_environment("asset-revoked", base_env={})
    except PermissionError as exc:
        assert "revoked" in str(exc)
    else:
        raise AssertionError("revoked device must not be launched")


def test_enrolled_agent_launcher_refuses_incomplete_credentials(monkeypatch):
    monkeypatch.setattr(launcher.agent_credentials, "get_agent_credential", lambda _asset_id: {
        "tenant_id": "tenant-a",
        "api_key": "agent-api-key-" + "a" * 40,
        "identity_secret": "short",
        "command_secret": "command-secret-" + "c" * 40,
        "status": "active",
    })
    try:
        launcher.build_agent_environment("asset-a", base_env={})
    except PermissionError as exc:
        assert "incomplete" in str(exc)
    else:
        raise AssertionError("incomplete enrollment must not launch")
