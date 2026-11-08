"""Deterministic source patch: avoid nested SQLite audit writes in command polling."""

PATCH_MARKER = "# CYBERGUARDIAN_PATCH: agent_commands_audit_v1"

PATCHED_ROUTE = '''# CYBERGUARDIAN_PATCH: agent_commands_audit_v1
@app.get("/v1/agent/commands")
async def agent_commands(asset_id: str, x_api_key: str = Depends(require_api_key)):
    """Agent pulls queued containment commands (single-use; expired commands skipped)."""
    ok_key, key_why = _agent_id.assert_not_admin_key_on_agent(x_api_key)
    if not ok_key:
        raise HTTPException(403, f"Agent commands rejected: {key_why}")
    now = time.time()
    audit_events = []
    with db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM agent_commands
            WHERE asset_id=? AND status='queued'
            ORDER BY created_at ASC LIMIT 20
            """,
            (asset_id,),
        ).fetchall()
        commands = []
        for r in rows:
            d = dict(r)
            try:
                d["parameters"] = json.loads(d.get("parameters") or "{}")
            except Exception:
                d["parameters"] = {}
            exp = d["parameters"].get("_expires_at")
            if exp is not None and float(exp) < now:
                conn.execute(
                    "UPDATE agent_commands SET status='expired', completed_at=? WHERE id=? AND status='queued'",
                    (now, d["id"]),
                )
                audit_events.append({
                    "event": "expired",
                    "command_id": d["id"],
                    "pending_action_id": d.get("pending_action_id") or "",
                    "action": d.get("action") or "",
                    "target": str(d.get("target") or ""),
                    "asset_id": asset_id,
                    "actor": "gateway",
                    "detail": "command TTL exceeded before delivery",
                    "result_ok": 0,
                })
                continue
            # Single-use: only deliver if still queued (compare-and-set).
            cur = conn.execute(
                "UPDATE agent_commands SET status='delivered', delivered_at=? WHERE id=? AND status='queued'",
                (now, d["id"]),
            )
            if cur.rowcount != 1:
                continue
            commands.append(d)
            audit_events.append({
                "event": "delivered",
                "command_id": d["id"],
                "pending_action_id": d.get("pending_action_id") or "",
                "action": d.get("action") or "",
                "target": str(d.get("target") or ""),
                "asset_id": asset_id,
                "decision_id": d.get("decision_id") or "",
                "detection_id": d.get("detection_id") or "",
                "actor": "agent",
                "detail": "pulled by agent (single-use)",
            })

    # Audit writes use a separate SQLite connection. Commit the command state
    # transaction first to prevent nested writers from locking the database.
    for event in audit_events:
        write_audit(**event)
    return {"asset_id": asset_id, "count": len(commands), "commands": commands}
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
