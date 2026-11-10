from __future__ import annotations

import importlib
import json
import sys
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))

REQUIRED_EVENTS = {
    "pilot_health_check",
    "pilot_client_mode_on",
    "pilot_issue_created",
    "pilot_remediation_blocked",
}


def _load_gateway(tmp_path, monkeypatch):
    data_dir = tmp_path / "gateway-data"
    data_dir.mkdir(mode=0o700)
    monkeypatch.setenv("CG_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CG_PRODUCTION", "0")
    monkeypatch.setenv("CG_REQUIRE_AGENT_IDENTITY", "0")
    monkeypatch.setenv("CYBERGUARDIAN_API_KEY", "admin-secret-" + "a" * 40)
    monkeypatch.setenv("CG_DASHBOARD_API_KEY", "dashboard-secret-" + "b" * 40)
    monkeypatch.setenv("CG_NAD_API_KEY", "nad-secret-" + "c" * 40)
    monkeypatch.setenv("CG_OPERATOR_ASSERTION_SECRET", "operator-secret-" + "d" * 40)
    monkeypatch.setenv("DECISION_SERVICE_API_KEY", "decision-secret-" + "e" * 40)

    import runtime_paths
    import agent_credentials
    import agent_identity
    import operator_context
    importlib.reload(runtime_paths)
    importlib.reload(agent_credentials)
    importlib.reload(agent_identity)
    importlib.reload(operator_context)
    import main
    importlib.reload(main)

    main._mod.DB_PATH = data_dir / "gateway.sqlite3"
    main._mod.GATE_CFG = data_dir / "gate_config.json"
    main._mod.CREDS_PATH = data_dir / "credentials.json"
    main._mod.CREDS_PATH.write_text(
        '{"audit_checkpoint_key_hex":"' + "9f" * 32 + '"}', encoding="utf-8"
    )
    main._mod.CREDS_PATH.chmod(0o600)
    main._AUDIT_LEDGER_PATH = data_dir / "audit_ledger.jsonl"
    return main, data_dir, "admin-secret-" + "a" * 40


def test_empty_audit_ledger_is_not_ready(tmp_path, monkeypatch):
    main, data_dir, _ = _load_gateway(tmp_path, monkeypatch)
    result = main._pilot_audit_readiness(str(uuid.uuid4()))
    assert result["ok"] is False
    assert result["records"] == 0
    assert "empty" in result["detail"]


def test_populated_valid_ledger_requires_all_events_for_same_pilot_run(tmp_path, monkeypatch):
    main, data_dir, _ = _load_gateway(tmp_path, monkeypatch)
    run_id = str(uuid.uuid4())
    for event in sorted(REQUIRED_EVENTS):
        main._audit_ledger.append_event(
            main._AUDIT_LEDGER_PATH,
            {"fields": {
                "event": event,
                "detail": json.dumps({
                    "pilot_run_id": run_id,
                    "tenant_id": "tenant-a",
                    "result_status": "ok",
                }, sort_keys=True),
            }},
        )

    verified = main._audit_ledger.verify_ledger(main._AUDIT_LEDGER_PATH)
    result = main._pilot_audit_readiness(run_id)
    assert verified["valid"] is True
    assert verified["records"] == 4
    assert result["ok"] is True
    assert set(result["events"]) == REQUIRED_EVENTS


def test_unreadable_audit_ledger_fails_closed(tmp_path, monkeypatch):
    main, data_dir, _ = _load_gateway(tmp_path, monkeypatch)

    def unreadable(_path):
        raise PermissionError("simulated audit storage denial")

    monkeypatch.setattr(main._audit_ledger, "_verify_ledger_unlocked", unreadable)
    result = main._pilot_audit_readiness(str(uuid.uuid4()))
    assert result["ok"] is False
    assert "unreadable" in result["detail"]


def test_corrupted_audit_ledger_fails_closed(tmp_path, monkeypatch):
    main, data_dir, _ = _load_gateway(tmp_path, monkeypatch)
    main._AUDIT_LEDGER_PATH.write_text('{"corrupt":true}\\n', encoding="utf-8")
    result = main._pilot_audit_readiness(str(uuid.uuid4()))
    assert result["ok"] is False
    assert "integrity" in result["detail"]


def test_pilot_actions_write_durable_events_and_scorecard_checks_them(tmp_path, monkeypatch):
    main, data_dir, admin_key = _load_gateway(tmp_path, monkeypatch)
    run_id = str(uuid.uuid4())
    headers = {
        "X-API-Key": admin_key,
        "X-Tenant-ID": "default",
        "X-CG-Pilot-Run-ID": run_id,
    }
    with TestClient(main.app) as client:
        health = client.get("/health", headers=headers)
        assert health.status_code == 200, health.text

        mode = client.post(
            "/v1/client-mode", headers=headers, json={"client_mode": True}
        )
        assert mode.status_code == 200, mode.text
        assert mode.json()["client_mode"] is True

        issue = client.post(
            "/v1/issues/remember",
            headers=headers,
            json={
                "title": "DRY-RUN synthetic credential-access simulation",
                "asset_id": "linux-localhost",
                "severity": "high",
                "tags": ["credential_access", "dry-run", "synthetic"],
                "indicators": {"pid": "4242", "source": "owner-pilot-validation"},
            },
        )
        assert issue.status_code == 200, issue.text

        remediation = client.post(
            "/v1/issues/auto-remediate", headers=headers, json={}
        )
        assert remediation.status_code == 200, remediation.text
        assert remediation.json()["status"] == "blocked"

        scorecard = client.get("/v1/pilot/scorecard", headers=headers)
        assert scorecard.status_code == 200, scorecard.text
        body = scorecard.json()
        audit = next(item for item in body["checks"] if item["id"] == "audit_ready")
        assert audit["ok"] is True, body
        assert set(body["audit_evidence"]["verified_events"]) == REQUIRED_EVENTS
        assert body["audit_evidence"]["records"] >= 4
