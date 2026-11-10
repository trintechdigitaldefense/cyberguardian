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


def test_client_health_script_fails_when_any_service_is_unhealthy():
    source = (ROOT / "scripts" / "client_health.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in source
    assert '[ "$fail" -eq 0 ]' in source
