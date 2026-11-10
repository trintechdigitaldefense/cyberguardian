from __future__ import annotations

import importlib
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))


def _load_gateway(tmp_path, monkeypatch):
    data_dir = tmp_path / "gateway-data"
    data_dir.mkdir(mode=0o700)
    monkeypatch.setenv("CG_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CG_PRODUCTION", "1")
    monkeypatch.setenv("CG_REQUIRE_AGENT_IDENTITY", "1")
    monkeypatch.setenv("CG_REQUIRE_COMMAND_SIG", "1")
    dashboard_key = "dashboard-secret-" + "b" * 40
    monkeypatch.setenv("CYBERGUARDIAN_API_KEY", "admin-secret-" + "a" * 40)
    monkeypatch.setenv("CG_DASHBOARD_API_KEY", dashboard_key)
    monkeypatch.setenv("CG_NAD_API_KEY", "nad-secret-" + "c" * 40)
    monkeypatch.setenv("CG_OPERATOR_ASSERTION_SECRET", "operator-secret-" + "d" * 40)
    monkeypatch.setenv("DECISION_SERVICE_API_KEY", "decision-secret-" + "e" * 40)

    import runtime_paths
    import agent_credentials
    import agent_identity
    importlib.reload(runtime_paths)
    importlib.reload(agent_credentials)
    importlib.reload(agent_identity)
    import main
    importlib.reload(main)
    main._mod.DB_PATH = data_dir / "gateway.sqlite3"
    main._mod.GATE_CFG = data_dir / "gate_config.json"
    main._mod.CREDS_PATH = data_dir / "credentials.json"
    main._mod.CREDS_PATH.write_text('{"audit_checkpoint_key_hex":"' + "9f" * 32 + '"}', encoding="utf-8")
    main._mod.CREDS_PATH.chmod(0o600)
    main._AUDIT_LEDGER_PATH = data_dir / "audit_ledger.jsonl"
    return main, dashboard_key, data_dir


def _auth_headers(main, dashboard_key, tenant_id="tenant-a", request_id="historical-read"):
    from operator_context import mint_assertion
    secret = "operator-secret-" + "d" * 40
    assertion = mint_assertion(
        secret=secret, subject="operator-a", role="admin",
        tenant_id=tenant_id, method="GET", path="/v1/audit/history",
        request_id=request_id,
    )
    return {
        "X-API-Key": dashboard_key,
        "X-Tenant-ID": tenant_id,
        "X-CG-Operator-Assertion": assertion,
        "X-Request-ID": request_id,
    }


def _seed(main, tenant_id, event, at):
    from operator_context import CURRENT_OPERATOR
    token = CURRENT_OPERATOR.set({
        "sub": "seed-operator", "role": "admin", "tenant_id": tenant_id,
        "request_id": "seed-" + event,
    })
    original_time = main._audit_ledger.time.time
    try:
        main._audit_ledger.time.time = lambda: at
        main._mod.write_audit(
            event=event, action="test", target="",
            actor="seed-operator", detail="historical fixture", result_ok=1,
        )
    finally:
        main._audit_ledger.time.time = original_time
        CURRENT_OPERATOR.reset(token)


def test_historical_audit_window_is_tenant_scoped_and_start_inclusive_end_exclusive(tmp_path, monkeypatch):
    main, dashboard_key, _ = _load_gateway(tmp_path, monkeypatch)
    start = datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp()
    middle = datetime(2026, 11, 5, 12, tzinfo=timezone.utc).timestamp()
    end = datetime(2026, 11, 10, tzinfo=timezone.utc).timestamp()
    _seed(main, "tenant-a", "tenant-a-at-start", start)
    _seed(main, "tenant-a", "tenant-a-inside", middle)
    _seed(main, "tenant-a", "tenant-a-at-end", end)
    _seed(main, "tenant-b", "tenant-b-inside", middle)

    with TestClient(main.app) as client:
        params = {"start": "2026-11-01T00:00:00Z", "end": "2026-11-10T00:00:00Z", "limit": 1}
        first = client.get("/v1/audit/history", params=params, headers=_auth_headers(main, dashboard_key))
        assert first.status_code == 200, first.text
        body = first.json()
        assert body["tenant_id"] == "tenant-a"
        assert body["boundary"] == "[start, end)"
        assert body["timezone"] == "UTC"
        assert body["total"] == 2
        assert body["has_more"] is True
        assert body["items"][0]["event"] == "tenant-a-at-start"
        assert body["items"][0]["tenant_id"] == "tenant-a"

        next_params = {**params, "offset": 1, "snapshot_head": body["snapshot_head"]}
        second = client.get(
            "/v1/audit/history", params=next_params,
            headers=_auth_headers(main, dashboard_key, request_id="historical-page-2"),
        )
        assert second.status_code == 200, second.text
        assert second.json()["snapshot_head"] == body["snapshot_head"]
        assert second.json()["total"] == body["total"]
        assert second.json()["items"][0]["event"] == "tenant-a-inside"
        assert all(item["event"] != "tenant-b-inside" for item in body["items"] + second.json()["items"])
        assert all(item["event"] != "tenant-a-at-end" for item in body["items"] + second.json()["items"])
        assert len({item["source_record_id"] for item in body["items"] + second.json()["items"]}) == 2


def test_historical_audit_rejects_missing_auth_invalid_period_and_tenant_override(tmp_path, monkeypatch):
    main, dashboard_key, _ = _load_gateway(tmp_path, monkeypatch)
    with TestClient(main.app) as client:
        params = {"start": "2026-11-01T00:00:00Z", "end": "2026-11-02T00:00:00Z"}
        no_assertion = client.get(
            "/v1/audit/history", params=params,
            headers={"X-API-Key": dashboard_key, "X-Tenant-ID": "tenant-a"},
        )
        assert no_assertion.status_code == 401
        headers = _auth_headers(main, dashboard_key)
        naive = client.get(
            "/v1/audit/history",
            params={"start": "2026-11-01T00:00:00", "end": "2026-11-02T00:00:00Z"},
            headers=headers,
        )
        assert naive.status_code == 422
        reversed_window = client.get(
            "/v1/audit/history",
            params={"start": "2026-11-02T00:00:00Z", "end": "2026-11-01T00:00:00Z"},
            headers=_auth_headers(main, dashboard_key, request_id="historical-reversed"),
        )
        assert reversed_window.status_code == 422
        override = client.get(
            "/v1/audit/history",
            params={**params, "tenant_id": "tenant-b"},
            headers=_auth_headers(main, dashboard_key, request_id="historical-override"),
        )
        assert override.status_code == 403


def test_historical_audit_fails_closed_on_corrupt_ledger(tmp_path, monkeypatch):
    main, dashboard_key, data_dir = _load_gateway(tmp_path, monkeypatch)
    ledger = data_dir / "audit_ledger.jsonl"
    ledger.write_text('{"corrupt":true}\\n', encoding="utf-8")
    with TestClient(main.app) as client:
        response = client.get(
            "/v1/audit/history",
            params={"start": "2026-11-01T00:00:00Z", "end": "2026-11-02T00:00:00Z"},
            headers=_auth_headers(main, dashboard_key),
        )
        assert response.status_code == 503
