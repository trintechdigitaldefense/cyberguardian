#!/usr/bin/env python3
"""Compose-only supervised workflow acceptance: decision, gate, command, audit, report."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control-plane" / "api"))
sys.path.insert(0, str(ROOT / "agents" / "linux-ebpf"))

import agent_credentials
import command_signing
import containment
from operator_context import mint_assertion

BASE = os.environ.get("CG_R4_API_URL", "http://127.0.0.1:8080")
TENANT = "default"


def call(method: str, path: str, *, payload=None, headers=None):
    request_headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        BASE + path, data=data, headers=request_headers, method=method.upper()
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read()
            return response.status, dict(response.headers.items()), json.loads(raw or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"{method} {path} returned HTTP {exc.code}: {detail}") from exc


def operator_headers(method: str, path: str, request_id: str):
    assertion = mint_assertion(
        secret=os.environ["CG_OPERATOR_ASSERTION_SECRET"],
        subject="compose-ci-admin",
        role="admin",
        tenant_id=TENANT,
        method=method,
        path=path,
        request_id=request_id,
    )
    return {
        "X-API-Key": os.environ["CG_DASHBOARD_API_KEY"],
        "X-Tenant-ID": TENANT,
        "X-CG-Operator-Assertion": assertion,
        "X-Request-ID": request_id,
    }


def main() -> int:
    agent = agent_credentials.get_agent_credential("compose-host")
    assert agent and agent.get("status") == "active", "Compose test agent must be enrolled and active"
    agent_headers = {"X-API-Key": agent["api_key"], "X-Tenant-ID": TENANT}
    nad_headers = {"X-API-Key": os.environ["CG_NAD_API_KEY"]}

    # This high-severity event forces a decision with human-gated actions.
    status, _, detection = call(
        "POST",
        "/v1/detections",
        headers=nad_headers,
        payload={
            "asset_id": "compose-host",
            "source": "nad-processor",
            "severity": "high",
            "confidence": 0.99,
            "title": "R4 supervised CI acceptance event",
            "description": "Synthetic high-risk event in a disposable Compose stack",
            "indicators": {},
            "tags": ["r4-ci-supervised"],
        },
    )
    assert 200 <= status < 300, detection

    gate_status, _, gate = call(
        "GET", "/v1/gate", headers=operator_headers("GET", "/v1/gate", "r4-gate-list")
    )
    assert gate_status == 200, gate
    pending = gate.get("pending") or gate.get("items") or []
    host_actions = [
        item for item in pending
        if str(item.get("target") or item.get("asset_id") or "") == "compose-host"
    ]
    def action_name(item):
        return str(item.get("action") or item.get("action_type") or "").lower()

    approve_item = next((item for item in host_actions if action_name(item) == "escalate"), None)
    reject_item = next((item for item in host_actions if action_name(item) == "isolate_host"), None)
    assert approve_item and reject_item, {
        "detail": "high-severity detection did not stage both human-gated actions",
        "detection": detection,
        "gate": gate,
    }
    approve_id = str(approve_item.get("id") or approve_item.get("pending_action_id") or "")
    reject_id = str(reject_item.get("id") or reject_item.get("pending_action_id") or "")
    assert approve_id and reject_id and approve_id != reject_id

    approve_path = f"/v1/gate/approve/{approve_id}"
    approve_status, _, approved = call(
        "POST", approve_path,
        headers=operator_headers("POST", approve_path, "r4-gate-approve"),
    )
    assert approve_status == 200, approved

    reject_path = f"/v1/gate/reject/{reject_id}"
    reject_status, _, rejected = call(
        "POST", reject_path,
        headers=operator_headers("POST", reject_path, "r4-gate-reject"),
    )
    assert reject_status == 200, rejected

    poll_status, _, polled = call(
        "GET", "/v1/agent/commands?asset_id=compose-host", headers=agent_headers
    )
    assert poll_status == 200, polled
    commands = polled.get("commands") or []
    approved_command = next(
        (
            item for item in commands
            if str(item.get("pending_action_id") or item.get("approval_ref") or "") == approve_id
        ),
        None,
    )
    assert approved_command, {"detail": "approved command was not delivered", "commands": commands}
    assert not any(
        str(item.get("pending_action_id") or item.get("approval_ref") or "") == reject_id
        for item in commands
    ), "rejected action must never be delivered"

    expected_signature = command_signing.sign_command(
        approved_command, agent["command_secret"]
    )
    assert expected_signature == approved_command.get("signature"), "delivered command signature is invalid"
    assert approved_command.get("action") == "escalate", "CI must execute only the non-disruptive action"

    # The agent's escalate handler is a no-host-change action. Run the actual
    # containment dispatcher and report its result; no firewall/process change
    # is performed by this workflow.
    execution = containment.execute_command(approved_command)
    assert execution.get("ok") is True, execution
    command_result = {
        "command_id": approved_command.get("id") or approved_command.get("command_id"),
        "asset_id": "compose-host",
        "action": approved_command["action"],
        "target": approved_command["target"],
        "ok": True,
        "detail": "R4 Compose CI non-disruptive action completed",
        "result": execution,
    }
    canonical = json.dumps(
        {
            "kind": "POST",
            "path": "/v1/agent/command-result",
            "payload": command_result,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    result_headers = {**agent_headers, "X-CG-Event-ID": event_id}
    result_status, _, result_body = call(
        "POST", "/v1/agent/command-result",
        payload=command_result, headers=result_headers,
    )
    assert result_status == 200, result_body
    replay_status, replay_headers, replay_body = call(
        "POST", "/v1/agent/command-result",
        payload=command_result, headers=result_headers,
    )
    assert replay_status == result_status and replay_body == result_body
    assert replay_headers.get("X-Cg-Idempotent-Replay", "").lower() == "true"

    audit_status, _, audit = call(
        "GET", "/v1/audit?limit=200",
        headers=operator_headers("GET", "/v1/audit", "r4-audit-read"),
    )
    assert audit_status == 200, audit
    command_id = str(command_result["command_id"])
    assert any(command_id in json.dumps(item, sort_keys=True) for item in audit.get("items", [])), audit

    report_status, _, report = call(
        "GET", "/v1/reports/weekly?tenant_id=default",
        headers=operator_headers("GET", "/v1/reports/weekly", "r4-weekly-report"),
    )
    assert report_status == 200, report
    print(json.dumps({
        "workflow": "detect-decision-stage-approve-reject-signed-delivery-safe-execution-audit-report",
        "detection_id": detection.get("detection_id") or detection.get("id"),
        "approved_action_id": approve_id,
        "rejected_action_id": reject_id,
        "command_id": command_id,
        "audit_records": len(audit.get("items", [])),
        "report_tenant": report.get("tenant_id", TENANT),
        "idempotent_replay": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
