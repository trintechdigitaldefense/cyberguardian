from __future__ import annotations

import importlib
import json
import sys
import time
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))
from service_auth import dashboard_scope_allows, nad_scope_allows


def test_dashboard_scope_allows_only_documented_dashboard_routes():
    for method, path in (
        ("GET", "/v1/risk/summary"),
        ("GET", "/v1/fleet"),
        ("GET", "/v1/gate"),
        ("GET", "/v1/client-mode"),
        ("GET", "/v1/issues/client-view"),
        ("GET", "/v1/inventory/report"),
        ("GET", "/v1/audit"),
        ("GET", "/v1/audit/history"),
        ("GET", "/v1/pilot/scorecard"),
        ("GET", "/v1/reports/weekly"),
        ("GET", "/v1/feedback"),
        ("GET", "/v1/hardening"),
        ("POST", "/v1/client-mode"),
        ("POST", "/v1/feedback/benign"),
    ):
        assert dashboard_scope_allows(method, path), (method, path)
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
    schema = main.app.openapi()
    for report_path in ("/v1/reports/weekly", "/v1/inventory/report", "/v1/risk/summary", "/v1/pilot/scorecard"):
        operation = schema.get("paths", {}).get(report_path, {}).get("get")
        assert operation is not None, f"dashboard report route missing from API schema: {report_path}"
        parameter_names = {item.get("name") for item in operation.get("parameters", [])}
        assert "tenant_id" in parameter_names, (
            f"dashboard report route lacks tenant filter: {report_path} {parameter_names}"
        )
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
    main._mod.CREDS_PATH.write_text(
        json.dumps({"audit_checkpoint_key_hex": "9f" * 32}),
        encoding="utf-8",
    )
    main._mod.CREDS_PATH.chmod(0o600)

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
            conn.execute(
                "INSERT OR REPLACE INTO assets(asset_id, tenant_id, hostname) VALUES (?, ?, ?)",
                ("asset-tenant-a-stale", "tenant-a", "host-a-stale"),
            )
            conn.execute(
                "INSERT OR REPLACE INTO assets(asset_id, tenant_id, hostname) VALUES (?, ?, ?)",
                ("asset-tenant-a-revoked", "tenant-a", "host-a-revoked"),
            )
            conn.execute(
                "UPDATE assets SET last_seen=?, status='online' WHERE asset_id=?",
                (time.time(), "asset-tenant-a"),
            )
            conn.execute(
                "UPDATE assets SET last_seen=?, status='online' WHERE asset_id=?",
                (time.time() - 3600, "asset-tenant-a-stale"),
            )
            conn.execute(
                "UPDATE assets SET last_seen=?, status='online' WHERE asset_id=?",
                (time.time(), "asset-tenant-b"),
            )
            conn.execute(
                "UPDATE assets SET last_seen=?, status='online' WHERE asset_id=?",
                (time.time(), "asset-tenant-a-revoked"),
            )
        agent_credentials.write_agent_credentials({
            "asset-tenant-a-revoked": {
                "tenant_id": "tenant-a", "api_key": "revoked-key",
                "identity_secret": "revoked-identity", "command_secret": "revoked-command",
                "status": "revoked",
            }
        })
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
        fresh_asset = next(item for item in fleet_items if item.get("asset_id") == "asset-tenant-a")
        stale_asset = next(item for item in fleet_items if item.get("asset_id") == "asset-tenant-a-stale")
        assert fresh_asset["lifecycle"] == "online", authorized.text
        assert stale_asset["lifecycle"] == "offline", authorized.text
        assert stale_asset["stale"] is True, authorized.text
        revoked_asset = next(item for item in fleet_items if item.get("asset_id") == "asset-tenant-a-revoked")
        assert revoked_asset["lifecycle"] == "revoked", authorized.text
        assert revoked_asset["status"] == "revoked", authorized.text

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

        # Positive approval/rejection paths require a real tenant-bound
        # pending_actions row; a queued agent command alone is not an approval.
        def seed_pending_action(action_id, tenant_id="tenant-a", asset_id="asset-tenant-a"):
            with main._mod.db() as conn:
                schema = conn.execute("PRAGMA table_info(pending_actions)").fetchall()
                columns = {str(row["name"]): row for row in schema}
                assert "id" in columns
                values = {
                    "id": action_id,
                    "tenant_id": tenant_id,
                    "status": "pending",
                    "action": "isolate_host",
                    "action_type": "isolate_host",
                    "target": asset_id,
                    "created_at": time.time(),
                    "updated_at": time.time(),
                    "reason": "R4 supervised gate acceptance",
                    "parameters": "{}",
                    "metadata": "{}",
                }
                for name, column in columns.items():
                    if name in values or not column["notnull"] or column["dflt_value"] is not None or column["pk"]:
                        continue
                    if "time" in name:
                        values[name] = time.time()
                    elif "status" in name or "state" in name:
                        values[name] = "pending"
                    elif "action" in name:
                        values[name] = "isolate_host"
                    elif "target" in name or "asset" in name:
                        values[name] = "asset-tenant-a"
                    elif "parameter" in name or "metadata" in name or "result" in name:
                        values[name] = "{}"
                    elif "reason" in name or "detail" in name:
                        values[name] = "R4 supervised gate acceptance"
                    elif "tenant" in name:
                        values[name] = "tenant-a"
                    elif "id" in name:
                        values[name] = action_id
                    elif "INT" in str(column["type"]).upper():
                        values[name] = 0
                    else:
                        values[name] = ""
                values = {name: value for name, value in values.items() if name in columns}
                names = list(values)
                placeholders = ", ".join("?" for _ in names)
                conn.execute(
                    f"INSERT INTO pending_actions ({', '.join(names)}) VALUES ({placeholders})",
                    [values[name] for name in names],
                )

        approve_id = "pending-tenant-a-approve"
        # A real tenant-B pending action must remain invisible to a
        # tenant-A operator even when the legacy table has no tenant_id or
        # asset_id columns and ownership must be resolved from its target.
        seed_pending_action(
            "pending-tenant-b-real", tenant_id="tenant-b", asset_id="asset-tenant-b"
        )
        cross_tenant_real_assertion = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="POST",
            path="/v1/gate/approve/pending-tenant-b-real",
            request_id="integration-gate-real-cross-tenant",
        )
        cross_tenant_real = client.post(
            "/v1/gate/approve/pending-tenant-b-real",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": cross_tenant_real_assertion},
        )
        assert cross_tenant_real.status_code == 403, cross_tenant_real.text

        approve_id = "pending-tenant-a-approve"
        seed_pending_action(approve_id)
        main._mod.queue_agent_command(
            asset_id="asset-tenant-a",
            action="isolate_host",
            target="asset-tenant-a",
            parameters={"reason": "R4 supervised approval test"},
            pending_action_id=approve_id,
            ttl_seconds=300,
        )
        approve_assertion = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="POST",
            path=f"/v1/gate/approve/{approve_id}",
            request_id="integration-gate-approve",
        )
        approved = client.post(
            f"/v1/gate/approve/{approve_id}",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": approve_assertion},
        )
        assert approved.status_code == 200, approved.text
        with main._mod.db() as conn:
            approved_row = conn.execute(
                "SELECT * FROM pending_actions WHERE id=?", (approve_id,)
            ).fetchone()
        assert approved_row is not None
        if "status" in approved_row.keys():
            assert str(approved_row["status"]).lower() in {"approved", "queued", "staged"}

        reject_id = "pending-tenant-a-reject"
        seed_pending_action(reject_id)
        main._mod.queue_agent_command(
            asset_id="asset-tenant-a",
            action="isolate_host",
            target="asset-tenant-a",
            parameters={"reason": "R4 supervised rejection test"},
            pending_action_id=reject_id,
            ttl_seconds=300,
        )
        reject_assertion = mint_assertion(
            secret=assertion_secret, subject="operator-a", role="admin",
            tenant_id="tenant-a", method="POST",
            path=f"/v1/gate/reject/{reject_id}",
            request_id="integration-gate-reject",
        )
        rejected = client.post(
            f"/v1/gate/reject/{reject_id}",
            headers={**dashboard_headers, "X-CG-Operator-Assertion": reject_assertion},
        )
        assert rejected.status_code == 200, rejected.text
        with main._mod.db() as conn:
            rejected_row = conn.execute(
                "SELECT * FROM pending_actions WHERE id=?", (reject_id,)
            ).fetchone()
        assert rejected_row is not None
        if "status" in rejected_row.keys():
            assert str(rejected_row["status"]).lower() in {"rejected", "cancelled", "denied"}

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

        from audit_ledger import verify_ledger
        ledger_path = data_dir / "audit_ledger.jsonl"
        ledger_status = verify_ledger(ledger_path)
        assert ledger_status["valid"] is True, ledger_status
        ledger_records = [json.loads(line) for line in ledger_path.read_text().splitlines()]
        assert any(
            "operator_request_started" in str(record.get("event"))
            and "operator-a" in str(record.get("event"))
            for record in ledger_records
        ), ledger_records
