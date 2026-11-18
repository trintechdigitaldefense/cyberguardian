from __future__ import annotations

import importlib
import asyncio
import json
import sys
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import StreamingResponse

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
def test_pilot_action_is_not_started_when_preflight_audit_write_fails(tmp_path, monkeypatch):
    main, data_dir, admin_key = _load_gateway(tmp_path, monkeypatch)
    # Begin from a known disabled state so the test can detect any mutation.
    main._mod.save_gate({"client_mode": False})
    run_id = str(uuid.uuid4())
    headers = {
        "X-API-Key": admin_key,
        "X-Tenant-ID": "default",
        "X-CG-Pilot-Run-ID": run_id,
        "X-Request-ID": "pilot-preflight-failure",
    }

    def fail_audit(**_kwargs):
        raise PermissionError("simulated audit ledger outage")

    monkeypatch.setattr(main._mod, "write_audit", fail_audit)
    with TestClient(main.app) as client:
        response = client.post(
            "/v1/client-mode", headers=headers, json={"client_mode": True}
        )

    assert response.status_code == 503
    assert response.json()["operation_status"] == "not_started"
    assert response.json()["operation_id"]
    assert main._mod.load_gate()["client_mode"] is False


def test_pilot_action_reports_unknown_outcome_if_completion_audit_fails(tmp_path, monkeypatch):
    main, data_dir, admin_key = _load_gateway(tmp_path, monkeypatch)
    main._mod.save_gate({"client_mode": False})
    run_id = str(uuid.uuid4())
    headers = {
        "X-API-Key": admin_key,
        "X-Tenant-ID": "default",
        "X-CG-Pilot-Run-ID": run_id,
        "X-Request-ID": "pilot-completion-failure",
    }
    original_write = main._mod.write_audit
    calls = []

    def fail_completion(**kwargs):
        calls.append(kwargs.get("event"))
        if kwargs.get("event") == "pilot_client_mode_on":
            raise PermissionError("simulated audit failure after operation")
        return original_write(**kwargs)

    monkeypatch.setattr(main._mod, "write_audit", fail_completion)
    with TestClient(main.app) as client:
        response = client.post(
            "/v1/client-mode", headers=headers, json={"client_mode": True}
        )

    assert calls == ["pilot_action_started", "pilot_client_mode_on"]
    assert response.status_code == 503
    assert response.json()["operation_status"] == "outcome_unknown"
    operation_id = response.json()["operation_id"]
    assert operation_id
    # The operation ran only after its durable intent was recorded. A 503 here
    # is explicitly an unknown outcome, not a safe signal to blindly retry.
    assert main._mod.load_gate()["client_mode"] is True
    integrity = main._audit_ledger.verify_ledger(main._AUDIT_LEDGER_PATH)
    assert integrity["valid"] is True
    records = [
        json.loads(line)
        for line in main._AUDIT_LEDGER_PATH.read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        record["event"]["fields"].get("event") == "pilot_action_started"
        and operation_id in record["event"]["fields"].get("detail", "")
        for record in records
    )




def _request_for_middleware(path, run_id):
    return Request({
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"x-cg-pilot-run-id", run_id.encode("ascii"))],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    })


def test_pilot_middleware_preserves_response_headers_and_background_task(tmp_path, monkeypatch):
    main, _, _ = _load_gateway(tmp_path, monkeypatch)
    completed = []
    monkeypatch.setattr(main._mod, "write_audit", lambda **_kwargs: None)
    original = StreamingResponse(
        iter([b"upstream payload"]),
        status_code=207,
        headers={
            "Content-Type": "application/vnd.cyberguardian+json; charset=utf-8",
            "Cache-Control": "private, no-store",
            "Access-Control-Allow-Origin": "https://client.example",
            "Set-Cookie": "first=one; HttpOnly",
        },
        background=BackgroundTask(lambda: completed.append("done")),
    )
    original.raw_headers.append((b"set-cookie", b"second=two; Secure"))

    async def call_next(_request):
        return original

    result = asyncio.run(
        main._r4_pilot_audit_evidence(
            _request_for_middleware("/health", str(uuid.uuid4())), call_next
        )
    )

    assert result.status_code == 207
    assert result.body == b"upstream payload"
    assert result.headers["content-type"] == "application/vnd.cyberguardian+json; charset=utf-8"
    assert result.headers["cache-control"] == "private, no-store"
    assert result.headers["access-control-allow-origin"] == "https://client.example"
    assert result.headers.getlist("set-cookie") == [
        "first=one; HttpOnly", "second=two; Secure"
    ]
    assert result.headers["content-length"] == str(len(b"upstream payload"))
    assert result.background is not None
    asyncio.run(result.background())
    assert completed == ["done"]


def test_scorecard_rewrite_preserves_safe_headers_and_background_task(tmp_path, monkeypatch):
    main, _, _ = _load_gateway(tmp_path, monkeypatch)
    completed = []
    run_id = str(uuid.uuid4())
    monkeypatch.setattr(
        main, "_pilot_audit_readiness",
        lambda _run_id: {"ok": True, "records": 4, "events": sorted(REQUIRED_EVENTS), "detail": "verified"},
    )
    original = StreamingResponse(
        iter([json.dumps({"checks": [{"id": "baseline", "ok": True}], "score": "1/1", "status": "green"}).encode("utf-8")]),
        status_code=200,
        media_type="application/json",
        headers={
            "Cache-Control": "private, no-store",
            "Access-Control-Allow-Origin": "https://client.example",
            "Set-Cookie": "first=one; HttpOnly",
            "ETag": '"stale-upstream-etag"',
        },
        background=BackgroundTask(lambda: completed.append("done")),
    )
    original.raw_headers.append((b"set-cookie", b"second=two; Secure"))

    async def call_next(_request):
        return original

    result = asyncio.run(
        main._r4_pilot_audit_evidence(
            _request_for_middleware("/v1/pilot/scorecard", run_id), call_next
        )
    )

    assert result.status_code == 200
    body = json.loads(result.body)
    assert body["audit_evidence"]["run_id"] == run_id
    assert result.headers["content-type"].startswith("application/json")
    assert result.headers["cache-control"] == "private, no-store"
    assert result.headers["access-control-allow-origin"] == "https://client.example"
    assert result.headers.getlist("set-cookie") == [
        "first=one; HttpOnly", "second=two; Secure"
    ]
    assert "etag" not in result.headers
    assert result.headers["content-length"] == str(len(result.body))
    assert result.background is not None
    asyncio.run(result.background())
    assert completed == ["done"]
