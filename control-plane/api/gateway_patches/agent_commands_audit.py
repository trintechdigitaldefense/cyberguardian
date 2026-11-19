"""Deterministic source patch: transactionally outbox agent command delivery."""

PATCH_MARKER = "# CYBERGUARDIAN_PATCH: agent_commands_audit_v1"

PATCHED_ROUTE = '''# CYBERGUARDIAN_PATCH: agent_commands_audit_v1
from transactional_outbox import SQLiteTransactionalOutbox as _SQLiteTransactionalOutbox
_CG_LIVE_OUTBOX = None
_CG_LIVE_OUTBOX_PATH = None


def _cg_live_outbox():
    global _CG_LIVE_OUTBOX, _CG_LIVE_OUTBOX_PATH
    current_path = Path(DB_PATH)
    if _CG_LIVE_OUTBOX is None or _CG_LIVE_OUTBOX_PATH != current_path:
        _CG_LIVE_OUTBOX = _SQLiteTransactionalOutbox(current_path)
        _CG_LIVE_OUTBOX_PATH = current_path
    return _CG_LIVE_OUTBOX


@app.get("/v1/agent/commands")
async def agent_commands(asset_id: str, request: Request, x_api_key: str = Depends(require_api_key)):
    """Atomically mark queued commands delivered and persist their audit outbox events."""
    import hashlib\n    ok_key, key_why = _agent_id.assert_not_admin_key_on_agent(x_api_key)
    if not ok_key:
        raise HTTPException(403, f"Agent commands rejected: {key_why}")

    tenant_id = str(getattr(request.state, "tenant_id", "") or "").strip()
    if not tenant_id:
        raise HTTPException(403, "Agent command polling requires an authenticated tenant context")
    now = time.time()
    delivered = []

    def apply_delivery(connection, operation_id):
        expired_ids = []
        delivered_ids = []
        delivered_actions = []
        audit_events = []
        rows = connection.execute(
            """SELECT * FROM agent_commands
               WHERE asset_id=? AND status='queued'
               ORDER BY created_at ASC LIMIT 20""",
            (asset_id,),
        ).fetchall()
        for row in rows:
            command = dict(row)
            try:
                command["parameters"] = json.loads(command.get("parameters") or "{}")
            except (TypeError, ValueError):
                command["parameters"] = {}
            expires_at = command["parameters"].get("_expires_at")
            if expires_at is not None and float(expires_at) < now:
                cursor = connection.execute(
                    """UPDATE agent_commands SET status='expired', completed_at=?
                       WHERE id=? AND status='queued'""",
                    (now, command["id"]),
                )
                if cursor.rowcount == 1:
                    expired_id = str(command["id"])
                    expired_ids.append(expired_id)
                    audit_events.append({
                        "event": "expired",
                        "command_id": expired_id,
                        "pending_action_id": command.get("pending_action_id") or "",
                        "action": command.get("action") or "",
                        "target": str(command.get("target") or ""),
                        "asset_id": asset_id,
                        "actor": "gateway",
                        "detail": "command TTL exceeded before delivery",
                        "result_ok": 0,
                    })
                continue

            cursor = connection.execute(
                """UPDATE agent_commands SET status='delivered', delivered_at=?
                   WHERE id=? AND status='queued'""",
                (now, command["id"]),
            )
            if cursor.rowcount != 1:
                continue
            delivered.append(command)
            delivered_ids.append(str(command["id"]))
            delivered_actions.append(str(command.get("action") or ""))
            audit_events.append({
                "event": "delivered",
                "command_id": str(command["id"]),
                "pending_action_id": command.get("pending_action_id") or "",
                "action": command.get("action") or "",
                "target": str(command.get("target") or ""),
                "asset_id": asset_id,
                "decision_id": command.get("decision_id") or "",
                "detection_id": command.get("detection_id") or "",
                "actor": "agent",
                "detail": "pulled by agent (single-use)",
            })

        return {
            "tenant_id": tenant_id,
            "asset_id": asset_id,
            "delivered_command_ids": delivered_ids,
            "delivered_actions": delivered_actions,
            "expired_command_ids": expired_ids,
            "audit_events": audit_events,
            "phase": "agent_commands_claimed",
        }

    request_fingerprint = hashlib.sha256(
        json.dumps(
            {"method": "GET", "path": "/v1/agent/commands",
             "asset_id": asset_id, "tenant_id": tenant_id},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    with db() as connection:
        _cg_live_outbox().execute_operation_on_connection(
            connection,
            tenant_id=tenant_id,
            idempotency_key=uuid.uuid4().hex,
            request_hash=request_fingerprint,
            handler=apply_delivery,
        )

    # Audit delivery is now durable in the same SQLite commit as the command
    # status transition. PR #17 supplies the supervised ledger dispatcher.
    return {"asset_id": asset_id, "count": len(delivered), "commands": delivered}
'''


def patch_source(source: str) -> str:
    if PATCH_MARKER in source:
        return source
    start_marker = '@app.get("/v1/agent/commands")'
    end_marker = "\n\nclass CommandResultIn("
    start = source.find(start_marker)
    end = source.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise ValueError("gateway command-poll route patch anchors not found")
    return source[:start] + PATCHED_ROUTE + source[end:]
