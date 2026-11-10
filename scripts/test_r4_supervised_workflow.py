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
    credential_file = Path(os.environ["CG_AGENT_TEST_CREDENTIAL_FILE"])
    agent = json.loads(credential_file.read_text(encoding="utf-8"))
    assert agent and agent.get("status") == "active", "Compose test agent must be enrolled and active"
    agent_headers = {"X-API-Key": agent["api_key"], "X-Tenant-ID": TENANT}
    nad_headers = {"X-API-Key": os.environ["CG_NAD_API_KEY"]}

    # Two independent high-severity detections each stage an isolate action.
    # The CI test approves one and rejects the other, but never executes either
    # disruptive containment command in the shared Compose namespace.
    def submit_high_detection(title: str, request_id: str):
        status, _, body = call(
            "POST",
            "/v1/detections",
            headers={**nad_headers, "X-Request-ID": request_id},
            payload={
                "asset_id": "compose-host",
                "source": "nad-processor",
                "severity": "high",
                "confidence": 0.99,
                "title": title,
                "description": "Synthetic high-risk event in a disposable Compose stack",
                "indicators": {},
                "tags": ["r4-ci-supervised", request_id],
            },
        )
        assert 200 <= status < 300, body
        return body

    detection_approve = submit_high_detection(
        "R4 supervised approval event", "r4-detection-approve"
    )
    detection_reject = submit_high_detection(
        "R4 supervised rejection event", "r4-detection-reject"
    )

    gate_path = "/v1/gate"
    gate_status, _, gate = call(
        "GET", gate_path, headers=operator_headers("GET", gate_path, "r4-gate-list")
    )
    assert gate_status == 200, gate
    pending = gate.get("pending") or gate.get("items") or []
    host_isolations = [
        item for item in pending
        if str(item.get("target") or item.get("asset_id") or "") == "compose-host"
        and str(item.get("action") or item.get("action_type") or "").lower() == "isolate_host"
    ]
    # Only the two actions created by this test are selected; ignore unrelated
    # pending records if a future CI fixture adds any.
    detection_ids = {
        str(detection_approve.get("detection_id") or ""),
        str(detection_reject.get("detection_id") or ""),
    }
    owned_actions = [
        item for item in host_isolations
        if str(item.get("detection_id") or "") in detection_ids
    ]
    assert len(owned_actions) == 2, {
        "detail": "expected one human-gated isolate action per synthetic detection",
        "detection_ids": sorted(detection_ids),
        "pending": pending,
    }
    owned_actions.sort(key=lambda item: float(item.get("created_at") or 0))
    approve_item, reject_item = owned_actions
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
    assert approved_command.get("action") == "isolate_host"
    approved_signature = command_signing.sign_command(
        approved_command, agent["command_secret"]
    )
    assert approved_signature == approved_command.get("signature"), "approved command signature is invalid"

    # A separately queued escalate command exercises actual safe agent dispatch.
    # It has no host-side effect and is not a substitute for the human gate.
    safe_command = next(
        (
            item for item in commands
            if str(item.get("pending_action_id") or "") == "r4-ci-safe-escalate"
        ),
        None,
    )
    assert safe_command and safe_command.get("action") == "escalate", {
        "detail": "safe non-disruptive command was not delivered",
        "commands": commands,
    }
    expected_signature = command_signing.sign_command(
        safe_command, agent["command_secret"]
    )
    assert expected_signature == safe_command.get("signature"), "safe command signature is invalid"

    execution = containment.execute_command(safe_command)
    assert execution.get("ok") is True, execution
    command_result = {
        "command_id": safe_command.get("id") or safe_command.get("command_id"),
        "asset_id": "compose-host",
        "action": safe_command["action"],
        "target": safe_command["target"],
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
        "detection_ids": sorted(detection_ids),
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
