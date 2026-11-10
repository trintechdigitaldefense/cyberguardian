from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_standalone_startup_passes_distinct_workload_credentials():
    source = (ROOT / "start.sh").read_text(encoding="utf-8")
    assert 'CG_DASHBOARD_API_KEY="$CG_DASHBOARD_API_KEY"' in source
    assert 'CG_NAD_API_KEY="$CG_NAD_API_KEY"' in source
    assert 'DECISION_SERVICE_API_KEY="$DECISION_SERVICE_API_KEY"' in source
    assert 'CG_OPERATOR_ASSERTION_SECRET="$CG_OPERATOR_ASSERTION_SECRET"' in source
    assert 'CG_NAD_API_KEY="$NAD_PROCESS_KEY"' in source
    assert 'CG_DASHBOARD_API_KEY="$DASHBOARD_PROCESS_KEY"' in source


def test_standalone_production_startup_fails_closed_and_binds_loopback():
    source = (ROOT / "start.sh").read_text(encoding="utf-8")
    assert 'BIND_HOST="127.0.0.1"' in source
    assert "all five production service credentials/secrets must be at least 32 bytes" in source
    assert "must all be unique" in source
    assert "must match data/credentials.json" in source
    assert "Production identity enforcement is enabled; skipping bootstrap agent." in source


def test_setup_credentials_generates_unique_service_identities_and_rotation():
    source = (ROOT / "scripts" / "setup_credentials.sh").read_text(encoding="utf-8")
    for field in (
        "dashboard_api_key",
        "nad_api_key",
        "operator_assertion_secret",
        "decision_service_api_key",
    ):
        assert f'"{field}"' in source
    assert "CG_ROTATE_BOOTSTRAP_AGENT_KEY" in source
