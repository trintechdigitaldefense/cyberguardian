from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pilot_day1_does_not_expose_or_print_agent_credentials():
    source = (ROOT / "scripts" / "pilot_day1.sh").read_text(encoding="utf-8")
    assert "AGENT_KEY" not in source
    assert "CYBERGUARDIAN_API_KEY=" not in source
    assert "X-API-Key:" not in source
    assert "No agent key or service secret has been printed." in source


def test_dry_run_reads_admin_key_in_process_not_curl_arguments():
    source = (ROOT / "scripts" / "dry_run_pilot.sh").read_text(encoding="utf-8")
    assert "urllib.request" in source
    assert "credentials.json" in source
    assert "X-API-Key" in source
    assert "curl -H" not in source
    assert 'KEY=$(python3' not in source


def test_dry_run_supplies_explicit_tenant_context_for_issue_memory():
    source = (ROOT / "scripts" / "dry_run_pilot.sh").read_text(encoding="utf-8")
    assert 'TENANT_ID="${CG_TENANT_ID:-default}"' in source
    assert '"X-Tenant-ID": os.environ.get("CG_TENANT_ID", "default")' in source
    assert "tenant context" in source


def test_client_health_script_fails_when_any_service_is_unhealthy():
    source = (ROOT / "scripts" / "client_health.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in source
    assert '[ "$fail" -eq 0 ]' in source


def test_start_refuses_to_launch_services_when_credentials_are_missing():
    source = (ROOT / "start.sh").read_text(encoding="utf-8")
    missing_branch = source.split('if [ ! -f "$CREDENTIALS_FILE" ]; then', 1)[1].split("\nfi", 1)[0]
    assert "Refusing to start any CyberGuardian service or agent." in missing_branch
    assert "exit 1" in missing_branch


def test_hardened_start_skips_bootstrap_agent_by_default():
    source = (ROOT / "start.sh").read_text(encoding="utf-8")
    assert "CG_ENABLE_LAB_BOOTSTRAP_AGENT" in source
    assert "hardened-mode safety default" in source


def test_hardened_production_start_can_launch_explicitly_enrolled_agent():
    source = (ROOT / "start.sh").read_text(encoding="utf-8")
    agent_block = source.split('if [ "${CG_DISABLE_LOCAL_AGENT:-0}" = "1" ]; then', 1)[1]
    strict_branch = agent_block.index('elif [ "$STRICT_AGENT_MODE" = "1" ]; then')
    hardened_bootstrap_guard = agent_block.index('elif { { [ "${CG_HARDENED:-0}" = "1" ]')
    enrolled_launch = agent_block.index("Starting enrolled agent")
    assert strict_branch < enrolled_launch < hardened_bootstrap_guard
    assert "CG_AGENT_ASSET_ID" in agent_block
    assert "scripts/run_enrolled_agent.py --asset-id" in agent_block


def test_credential_setup_never_prints_generated_secret_values():
    source = (ROOT / "scripts" / "setup_credentials.sh").read_text(encoding="utf-8")
    assert 'print(f"Admin API key' not in source
    assert 'print(f"Agent API key' not in source
    assert "Secret values are intentionally NOT printed." in source
