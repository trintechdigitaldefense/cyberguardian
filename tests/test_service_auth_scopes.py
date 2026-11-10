from __future__ import annotations

import importlib
import sys
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))
from service_auth import dashboard_scope_allows, nad_scope_allows


def test_dashboard_scope_allows_only_documented_dashboard_routes():
    assert dashboard_scope_allows("GET", "/v1/fleet")
    assert dashboard_scope_allows("POST", "/v1/gate/approve/action-7")
    assert dashboard_scope_allows("POST", "/v1/gate/reject/action-7")
    assert dashboard_scope_allows("POST", "/v1/rollback/asset-9")
    assert dashboard_scope_allows("POST", "/v1/feedback/benign")
    assert not dashboard_scope_allows("POST", "/v1/agent/commands")
    assert not dashboard_scope_allows("POST", "/v1/assets/register")
    assert not dashboard_scope_allows("GET", "/v1/credentials")
    assert not dashboard_scope_allows("DELETE", "/v1/fleet")
    assert not dashboard_scope_allows("POST", "/v1/rollback/../other")


def test_nad_scope_is_detection_submission_only():
    assert nad_scope_allows("POST", "/v1/detections")
    assert not nad_scope_allows("GET", "/v1/detections")
    assert not nad_scope_allows("POST", "/v1/gate/approve/action-7")
    assert not nad_scope_allows("GET", "/v1/fleet")



def test_gateway_enforces_dashboard_and_nad_service_boundaries(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from operator_context import mint_assertion

    data_dir = tmp_path / "controller-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CG_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CG_PRODUCTION", "1")
    monkeypatch.setenv("CG_REQUIRE_AGENT_IDENTITY", "1")
    monkeypatch.setenv("CG_REQUIRE_COMMAND_SIG", "1")
    admin_key = "admin-secret-" + "a" * 40
    dashboard_key = "dashboard-secret-" + "b" * 40
    nad_key = "nad-secret-" + "c" * 40
    assertion_secret = "operator-secret-" + "d" * 40
    decision_key = "decision-secret-" + "e" * 40
    monkeypatch.setenv("CYBERGUARDIAN_API_KEY", admin_key)
    monkeypatch.setenv("CG_DASHBOARD_API_KEY", dashboard_key)
    monkeypatch.setenv("CG_NAD_API_KEY", nad_key)
    monkeypatch.setenv("CG_OPERATOR_ASSERTION_SECRET", assertion_secret)
    monkeypatch.setenv("DECISION_SERVICE_API_KEY", decision_key)

    import runtime_paths
    import agent_credentials
    import agent_identity
    importlib.reload(runtime_paths)
    importlib.reload(agent_credentials)
    importlib.reload(agent_identity)
    import main
    importlib.reload(main)
    from operator_context import CURRENT_OPERATOR
    operator_token = CURRENT_OPERATOR.set({
        "sub": "operator-a", "role": "admin", "tenant_id": "tenant-a",
        "request_id": "admin-check",
    })
    try:
        assert main._mod.is_admin(dashboard_key)
        assert not main._mod.is_admin(nad_key)
    finally:
        CURRENT_OPERATOR.reset(operator_token)
    main._mod.DB_PATH = data_dir / "gateway.sqlite3"
    main._mod.GATE_CFG = data_dir / "gate_config.json"
    main._mod.CREDS_PATH = data_dir / "credentials.json"

    with TestClient(main.app) as client:
        with main._mod.db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO assets(asset_id, tenant_id, hostname) VALUES (?, ?, ?)",
                ("asset-tenant-a", "tenant-a", "host-a"),
            )
            conn.execute(
                "INSERT OR REPLACE INTO assets(asset_id, tenant_id, hostname) VALUES (?, ?, ?)",
                ("asset-tenant-b", "tenant-b", "host-b"),
            )
        main._mod.queue_agent_command(
            asset_id="asset-tenant-b",
            action="isolate_host",
            target="asset-tenant-b",
            parameters={},
            pending_action_id="pending-tenant-b",
            ttl_seconds=300,
        )
        dashboard_headers = {"X-API-Key": dashboard_key, "X-Tenant-ID": "tenant-a"}
        missing_assertion = client.get("/v1/fleet", headers=dashboard_headers)
        assert missing_assertion.status_code == 401

        nad_fleet_read = client.get("/v1/fleet", headers={"X-API-Key": nad_key})
        assert nad_fleet_read.status_code == 403

        dashboard_agent_access = client.get(
            "/v1/agent/commands?asset_id=host-a", headers=dashboard_headers
        )
        assert dashboard_agent_access.status_code == 403

        assertion = mint_assertion(
            secret=assertion_secret,
            subject="operator-a",
            role="admin",
            tenant_id="tenant-a",
            method="GET",
            path="/v1/fleet",
            request_id="integration-request-1",
        )
        authorized = client.get(
            "/v1/fleet",
            headers={
                **dashboard_headers,
                "X-CG-Operator-Assertion": assertion,
                "X-Request-ID": "integration-request-1",
            },
        )
        assert authorized.status_code == 200, authorized.text
        fleet_items = authorized.json().get("items", [])
        assert any(item.get("asset_id") == "asset-tenant-a" for item in fleet_items), authorized.text
        assert not any(item.get("asset_id") == "asset-tenant-b" for item in fleet_items), authorized.text

        audit_assertion = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="GET", path="/v1/audit",
            request_id="integration-audit-read",
        )
        audit_response = client.get(
            "/v1/audit?limit=40",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": audit_assertion},
        )
        assert audit_response.status_code == 200, audit_response.text
        audit_items = audit_response.json().get("items", [])
        assert any(
            item.get("actor") == "operator-a"
            and "actor_role" in str(item.get("detail", ""))
            and "tenant_id" in str(item.get("detail", ""))
            for item in audit_items
        ), audit_response.text
        from operator_context import CURRENT_OPERATOR
        tenant_b_token = CURRENT_OPERATOR.set({
            "sub": "operator-b", "role": "admin", "tenant_id": "tenant-b",
            "request_id": "tenant-b-audit-seed",
        })
        try:
            main._mod.write_audit(
                event="tenant-b-secret-event",
                action="test",
                target="asset-tenant-b",
                actor="operator-b",
                detail="tenant-b-only audit marker",
                result_ok=1,
            )
        finally:
            CURRENT_OPERATOR.reset(tenant_b_token)
        audit_after_seed_assertion = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="GET", path="/v1/audit",
            request_id="integration-audit-isolation",
        )
        audit_after_seed = client.get(
            "/v1/audit?limit=100",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": audit_after_seed_assertion},
        )
        assert audit_after_seed.status_code == 200, audit_after_seed.text
        assert not any(
            item.get("event") == "tenant-b-secret-event"
            for item in audit_after_seed.json().get("items", [])
        ), audit_after_seed.text

        query_override = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="GET", path="/v1/fleet",
            request_id="integration-query-override",
        )
        denied_query_override = client.get(
            "/v1/fleet?tenant_id=tenant-b",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": query_override},
        )
        assert denied_query_override.status_code == 403
        duplicate_query_override = client.get(
            "/v1/fleet?tenant_id=tenant-b&tenant_id=tenant-a",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": query_override},
        )
        assert duplicate_query_override.status_code == 403

        body_override = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="POST", path="/v1/client-mode",
            request_id="integration-body-override",
        )
        denied_body_override = client.post(
            "/v1/client-mode",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": body_override},
            json={"client_mode": True, "tenant_id": "tenant-b"},
        )
        assert denied_body_override.status_code == 403

        rollback_override = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="POST", path="/v1/rollback/asset-tenant-b",
            request_id="integration-rollback-override",
        )
        denied_rollback_override = client.post(
            "/v1/rollback/asset-tenant-b",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": rollback_override},
            json={"reason": "cross-tenant test"},
        )
        assert denied_rollback_override.status_code == 403

        gate_override = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="POST", path="/v1/gate/approve/pending-tenant-b",
            request_id="integration-gate-override",
        )
        denied_gate_override = client.post(
            "/v1/gate/approve/pending-tenant-b",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": gate_override},
        )
        assert denied_gate_override.status_code == 403

        denial_audit_assertion = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="GET", path="/v1/audit",
            request_id="integration-denial-audit",
        )
        denial_audit = client.get(
            "/v1/audit?limit=100",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": denial_audit_assertion},
        )
        assert denial_audit.status_code == 200, denial_audit.text
        assert any(
            item.get("event") == "operator_request_denied"
            and item.get("actor") == "operator-a"
            for item in denial_audit.json().get("items", [])
        ), denial_audit.text
