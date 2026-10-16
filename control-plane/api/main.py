"""
CyberGuardian API Gateway v1.1.0-pilot
Dual API keys, client mode, gate, fleet, issues, inventory, reports.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import issue_memory as _issue_mem

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "cyberguardian.db"
CREDS_PATH = DATA / "credentials.json"
GATE_CFG = DATA / "gate_config.json"
SERVICE_STARTED_AT = time.time()

DECISION_URL = os.getenv("DECISION_SERVICE_URL", "http://127.0.0.1:8001")

app = FastAPI(title="CyberGuardian API", version="1.1.0-pilot", docs_url="/docs", redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)


def load_creds() -> dict:
    if CREDS_PATH.exists():
        try:
            return json.loads(CREDS_PATH.read_text())
        except Exception:
            pass
    return {}


def admin_key() -> str:
    c = load_creds()
    return (c.get("api_key") or os.environ.get("CYBERGUARDIAN_API_KEY") or "").strip()


def agent_key() -> str:
    return (load_creds().get("agent_api_key") or "").strip()


def valid_keys() -> set:
    keys = set()
    for k in (admin_key(), agent_key()):
        if k:
            keys.add(k)
    return keys


def is_admin(key: str) -> bool:
    return bool(key) and key == admin_key() and key != ""


def require_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> str:
    if not x_api_key or x_api_key not in valid_keys():
        raise HTTPException(401, "Invalid or missing API Key. Use header: X-API-Key")
    return x_api_key


def require_admin(x_api_key: str = Depends(require_api_key)) -> str:
    if not is_admin(x_api_key):
        raise HTTPException(401, "Admin API key required")
    return x_api_key


def load_gate() -> dict:
    default = {
        "client_mode": True,
        "require_approval_for": ["isolate_host", "kill_process", "block_ip"],
        "auto_alert_ok": True,
    }
    if GATE_CFG.exists():
        try:
            default.update(json.loads(GATE_CFG.read_text()))
        except Exception:
            pass
    return default


def save_gate(d: dict) -> dict:
    d = dict(d)
    d["updated_at"] = time.time()
    GATE_CFG.write_text(json.dumps(d, indent=2))
    try:
        GATE_CFG.chmod(0o600)
    except Exception:
        pass
    return d


@contextmanager
def db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                tenant_id TEXT DEFAULT 'default',
                hostname TEXT,
                asset_type TEXT DEFAULT 'endpoint',
                os TEXT,
                criticality TEXT DEFAULT 'medium',
                tags TEXT DEFAULT '[]',
                registered_at REAL,
                last_seen REAL,
                status TEXT DEFAULT 'online',
                agent_version TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS pending_actions (
                id TEXT PRIMARY KEY,
                action TEXT,
                target TEXT,
                parameters TEXT,
                reason TEXT,
                decision_id TEXT,
                detection_id TEXT,
                created_at REAL,
                status TEXT DEFAULT 'pending',
                approved_at REAL
            );
            CREATE TABLE IF NOT EXISTS detections_log (
                id TEXT PRIMARY KEY,
                tenant_id TEXT DEFAULT 'default',
                asset_id TEXT,
                title TEXT,
                severity TEXT,
                risk_score REAL,
                payload TEXT,
                created_at REAL
            );
            CREATE TABLE IF NOT EXISTS discovered_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT DEFAULT 'default',
                ip TEXT,
                hostname TEXT,
                mac TEXT,
                device_type TEXT,
                os_guess TEXT,
                open_ports TEXT,
                last_found REAL,
                UNIQUE(tenant_id, ip)
            );
            """
        )


@app.on_event("startup")
def _startup():
    init_db()
    if not GATE_CFG.exists():
        save_gate(load_gate())


def _uptime():
    secs = int(time.time() - SERVICE_STARTED_AT)
    return secs, f"{secs // 60}m {secs % 60}s"


class AssetRegister(BaseModel):
    asset_id: str
    hostname: Optional[str] = None
    asset_type: str = "endpoint"
    os: Optional[str] = None
    tags: List[str] = []
    criticality: str = "medium"
    agent_version: str = ""
    tenant_id: str = "default"


class DetectionIn(BaseModel):
    source: str = "agent"
    asset_id: str
    asset_type: str = "endpoint"
    severity: str = "medium"
    confidence: float = 0.7
    title: str
    description: str = ""
    indicators: Dict[str, Any] = {}
    tags: List[str] = []
    tenant_id: str = "default"


class IssueRememberIn(BaseModel):
    title: str
    asset_id: str
    severity: str = "medium"
    source: str = "agent"
    tags: List[str] = []
    indicators: Dict[str, Any] = {}
    description: str = ""
    detection_id: str = ""
    playbook_id: str = ""


@app.get("/health")
async def health():
    secs, human = _uptime()
    return {
        "status": "ok",
        "service": "api-gateway",
        "hardened": True,
        "version": "1.1.0-pilot",
        "uptime_seconds": secs,
        "uptime_human": human,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/v1/client-mode")
async def get_client_mode(x_api_key: str = Depends(require_api_key)):
    c = load_gate()
    return {
        "client_mode": bool(c.get("client_mode", True)),
        "require_approval_for": c.get("require_approval_for") or [],
        "auto_alert_ok": bool(c.get("auto_alert_ok", True)),
    }


@app.post("/v1/client-mode")
async def set_client_mode(payload: dict, x_api_key: str = Depends(require_admin)):
    c = load_gate()
    if "client_mode" in payload:
        c["client_mode"] = bool(payload["client_mode"])
    if "require_approval_for" in payload and isinstance(payload["require_approval_for"], list):
        c["require_approval_for"] = payload["require_approval_for"]
    c = save_gate(c)
    return {"status": "ok", "client_mode": c["client_mode"], "config": c}


@app.post("/v1/assets/register")
async def register_asset(payload: AssetRegister, x_api_key: str = Depends(require_api_key)):
    now = time.time()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO assets(asset_id, tenant_id, hostname, asset_type, os, criticality, tags, registered_at, last_seen, status, agent_version)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(asset_id) DO UPDATE SET
              hostname=excluded.hostname,
              last_seen=excluded.last_seen,
              status='online',
              agent_version=excluded.agent_version,
              tags=excluded.tags
            """,
            (
                payload.asset_id,
                payload.tenant_id,
                payload.hostname or payload.asset_id,
                payload.asset_type,
                payload.os or "",
                payload.criticality,
                json.dumps(payload.tags),
                now,
                now,
                "online",
                payload.agent_version,
            ),
        )
    return {"status": "registered", "asset_id": payload.asset_id, "tenant_id": payload.tenant_id}


@app.get("/v1/assets")
async def list_assets(x_api_key: str = Depends(require_api_key), tenant_id: str = "default"):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE tenant_id=? ORDER BY last_seen DESC", (tenant_id,)
        ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except Exception:
            d["tags"] = []
        items.append(d)
    return {"count": len(items), "items": items, "tenant_id": tenant_id}


@app.get("/v1/fleet")
async def fleet(x_api_key: str = Depends(require_api_key), tenant_id: str = "default"):
    now = time.time()
    with db() as conn:
        rows = conn.execute("SELECT * FROM assets WHERE tenant_id=?", (tenant_id,)).fetchall()
    items = []
    online = 0
    for r in rows:
        d = dict(r)
        age = now - (d.get("last_seen") or 0)
        d["seconds_since_seen"] = age
        d["status"] = "online" if age < 180 else "offline"
        if d["status"] == "online":
            online += 1
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except Exception:
            d["tags"] = []
        items.append(d)
    return {
        "tenant_id": tenant_id,
        "total": len(items),
        "online": online,
        "offline": len(items) - online,
        "items": items,
    }


@app.post("/v1/detections")
async def ingest_detection(payload: DetectionIn, x_api_key: str = Depends(require_api_key)):
    detection = {
        "detection_id": str(uuid.uuid4()),
        **payload.model_dump(),
        "timestamp": time.time(),
    }
    with db() as conn:
        conn.execute(
            "UPDATE assets SET last_seen=?, status='online' WHERE asset_id=?",
            (time.time(), payload.asset_id),
        )

    decision = {}
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.post(f"{DECISION_URL}/v1/decide", json=detection)
            resp.raise_for_status()
            decision = resp.json()
        except Exception as e:
            raise HTTPException(502, f"Decision service error: {e}")

    gate = load_gate()
    client_mode = bool(gate.get("client_mode", True))
    need_approval = set(gate.get("require_approval_for") or [])
    staged = []
    if client_mode:
        for act in decision.get("actions") or []:
            if act.get("action") in need_approval:
                pid = str(uuid.uuid4())
                with db() as conn:
                    conn.execute(
                        """
                        INSERT INTO pending_actions(id, action, target, parameters, reason, decision_id, detection_id, created_at, status)
                        VALUES(?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            pid,
                            act.get("action"),
                            act.get("target"),
                            json.dumps(act.get("parameters") or {}),
                            (act.get("reason") or "") + " [staged — client human gate]",
                            decision.get("decision_id"),
                            detection["detection_id"],
                            time.time(),
                            "pending",
                        ),
                    )
                staged.append(pid)
                act["auto_approved"] = False
                act["staged"] = True

    with db() as conn:
        conn.execute(
            """
            INSERT INTO detections_log(id, tenant_id, asset_id, title, severity, risk_score, payload, created_at)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                detection["detection_id"],
                payload.tenant_id,
                payload.asset_id,
                payload.title,
                payload.severity,
                decision.get("risk_score"),
                json.dumps({"detection": detection, "decision": decision}),
                time.time(),
            ),
        )

    try:
        _issue_mem.remember_issue(
            title=payload.title,
            asset_id=payload.asset_id,
            severity=payload.severity,
            source=payload.source,
            tags=payload.tags,
            indicators=payload.indicators,
            description=payload.description,
            detection_id=detection["detection_id"],
            playbook_id=(decision.get("playbook") or {}).get("playbook_id") or "",
        )
    except Exception:
        pass

    return {
        "detection_id": detection["detection_id"],
        "decision": decision,
        "client_mode": client_mode,
        "staged_action_ids": staged,
    }


@app.get("/v1/gate")
async def gate_status(x_api_key: str = Depends(require_api_key)):
    g = load_gate()
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM pending_actions WHERE status='pending' ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    pending = []
    for r in rows:
        d = dict(r)
        try:
            d["parameters"] = json.loads(d.get("parameters") or "{}")
        except Exception:
            d["parameters"] = {}
        pending.append(d)
    return {
        "gate": {
            "client_mode": bool(g.get("client_mode", True)),
            "require_approval_for": g.get("require_approval_for") or [],
            "auto_alert_ok": bool(g.get("auto_alert_ok", True)),
        },
        "pending_count": len(pending),
        "pending": pending,
    }


@app.post("/v1/gate/approve/{action_id}")
async def gate_approve(action_id: str, x_api_key: str = Depends(require_admin)):
    with db() as conn:
        row = conn.execute("SELECT * FROM pending_actions WHERE id=?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(404, "pending action not found")
        d = dict(row)
        conn.execute(
            "UPDATE pending_actions SET status='approved', approved_at=? WHERE id=?",
            (time.time(), action_id),
        )
    execution = {"status": "submitted"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                f"{DECISION_URL}/v1/execute",
                json={
                    "action": d["action"],
                    "target": d["target"],
                    "reason": d.get("reason") or "",
                    "auto_approved": True,
                },
            )
            execution = {"status": "ok", "body": r.json() if r.status_code < 400 else {"detail": r.text}}
    except Exception as e:
        execution = {"status": "error", "detail": str(e)}
    return {"status": "approved", "action": d, "execution": execution}


@app.post("/v1/gate/reject/{action_id}")
async def gate_reject(action_id: str, x_api_key: str = Depends(require_admin)):
    with db() as conn:
        row = conn.execute("SELECT * FROM pending_actions WHERE id=?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(404, "pending action not found")
        conn.execute(
            "UPDATE pending_actions SET status='rejected', approved_at=? WHERE id=?",
            (time.time(), action_id),
        )
    return {"status": "rejected", "action_id": action_id}


@app.post("/v1/issues/remember")
async def issues_remember(payload: IssueRememberIn, x_api_key: str = Depends(require_api_key)):
    rec = _issue_mem.remember_issue(
        title=payload.title,
        asset_id=payload.asset_id,
        severity=payload.severity,
        source=payload.source,
        tags=payload.tags,
        indicators=payload.indicators,
        description=payload.description,
        detection_id=payload.detection_id,
        playbook_id=payload.playbook_id,
    )
    return {"status": "ok", "issue": rec}


@app.get("/v1/issues")
async def issues_list(x_api_key: str = Depends(require_api_key), status: Optional[str] = None, limit: int = 100):
    items = _issue_mem.list_issues(status=status, limit=limit)
    return {"count": len(items), "items": items}


@app.get("/v1/issues/client-view")
async def issues_client_view(x_api_key: str = Depends(require_api_key)):
    items = _issue_mem.list_issues(limit=50)
    return {"count": len(items), "items": items, "client_mode": bool(load_gate().get("client_mode", True))}


@app.post("/v1/issues/auto-remediate")
async def issues_auto_remediate(x_api_key: str = Depends(require_admin)):
    gate = load_gate()
    if bool(gate.get("client_mode", True)):
        return {
            "status": "blocked",
            "reason": "Client Mode is ON — issues stay staged for human approval. Turn Client Mode OFF for auto-remediation of known issues.",
            "fixed": [],
        }
    fixed = []
    for issue in _issue_mem.list_issues(status="open", limit=50):
        if not issue.get("auto_fix_eligible"):
            continue
        actions = _issue_mem.known_auto_actions(issue)
        for a in actions:
            if a.get("action") == "alert_only":
                continue
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(
                        f"{DECISION_URL}/v1/execute",
                        json={
                            "action": a["action"],
                            "target": a["target"],
                            "reason": a.get("reason") or "auto-remediate",
                            "auto_approved": True,
                        },
                    )
                fixed.append({"issue_id": issue.get("id"), "action": a})
            except Exception:
                pass
        _issue_mem.update_issue(issue["id"], status="auto_fixed")
    return {"status": "ok", "fixed": fixed}


@app.get("/v1/risk/summary")
async def risk_summary(x_api_key: str = Depends(require_api_key), tenant_id: str = "default"):
    now = time.time()
    with db() as conn:
        assets = conn.execute("SELECT * FROM assets WHERE tenant_id=?", (tenant_id,)).fetchall()
        dets = conn.execute(
            "SELECT COUNT(*) AS c FROM detections_log WHERE tenant_id=? AND created_at > ?",
            (tenant_id, now - 86400),
        ).fetchone()
    online = sum(1 for a in assets if (now - (dict(a).get("last_seen") or 0)) < 180)
    return {
        "tenant_id": tenant_id,
        "total_assets": len(assets),
        "online": online,
        "high_risk_assets": 0,
        "open_detections": int(dets["c"] if dets else 0),
        "auto_healed_24h": 0,
        "timestamp": now,
    }


@app.get("/v1/inventory/report")
async def inventory_report(x_api_key: str = Depends(require_api_key)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM discovered_hosts ORDER BY last_found DESC LIMIT 200").fetchall()
    lines = [
        "CyberGuardian Inventory Report",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Hosts found: {len(rows)}",
        "-" * 48,
    ]
    for i, r in enumerate(rows, 1):
        d = dict(r)
        lines.append(
            f"{i}. {d.get('ip')} | host={d.get('hostname') or 'n/a'} | type={d.get('device_type') or 'unknown'}"
        )
    lines.append("-" * 48)
    lines.append("Note: Best-effort discovery, not a guaranteed asset database.")
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse("\n".join(lines))


@app.get("/v1/decisions/recent")
async def decisions_recent(x_api_key: str = Depends(require_api_key), limit: int = 20):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, asset_id, title, severity, risk_score, created_at FROM detections_log ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"count": len(rows), "items": [dict(r) for r in rows], "tenant_id": "default"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
