"""
CyberGuardian Decision Service v1.5.0-tier1 — risk scoring + playbooks + evidence.
"""
from __future__ import annotations

import time
import uuid
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from playbooks import match_playbook

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("decision-service")

app = FastAPI(title="CyberGuardian Decision Service", version="1.5.0-tier1")

PROTECTION_MODE = True  # enforce staged/executed actions when approved


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    ALERT_ONLY = "alert_only"
    ESCALATE = "escalate"


class Detection(BaseModel):
    detection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "unknown"
    asset_id: str
    asset_type: str = "endpoint"
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)
    title: str
    description: str = ""
    indicators: Dict[str, Any] = {}
    tags: List[str] = []
    timestamp: float = Field(default_factory=time.time)


class ActionRequest(BaseModel):
    action: ActionType
    target: str
    parameters: Dict[str, Any] = {}
    reason: str = ""
    auto_approved: bool = False


decisions_db: Dict[str, Dict] = {}
action_history: List[Dict] = []


def risk_score(sev: Severity, conf: float) -> float:
    base = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 0.95}[sev.value]
    return round(min(1.0, base * (0.5 + 0.5 * conf)), 3)


def plan_actions(det: Detection) -> List[ActionRequest]:
    actions: List[ActionRequest] = []
    pb = match_playbook(det.title, det.tags)
    pid = str(det.indicators.get("pid") or det.indicators.get("process_id") or "")
    if pb:
        for step in pb["steps"]:
            auto = bool(step.get("auto")) and PROTECTION_MODE
            target = det.asset_id
            if step["action"] == "kill_process":
                target = pid or det.asset_id
            if step["action"] == "block_ip":
                target = str(det.indicators.get("dst_ip") or det.indicators.get("ip") or det.asset_id)
            actions.append(
                ActionRequest(
                    action=ActionType(step["action"]),
                    target=target,
                    reason=step.get("desc", ""),
                    auto_approved=auto and step["action"] != "escalate",
                    parameters={"playbook": pb["id"]},
                )
            )
        return actions

    if det.severity in (Severity.HIGH, Severity.CRITICAL):
        actions.append(
            ActionRequest(
                action=ActionType.ISOLATE_HOST,
                target=det.asset_id,
                reason="High/critical severity",
                auto_approved=PROTECTION_MODE,
            )
        )
        if pid:
            actions.append(
                ActionRequest(
                    action=ActionType.KILL_PROCESS,
                    target=pid,
                    reason="Terminate suspicious process",
                    auto_approved=PROTECTION_MODE,
                )
            )
        actions.append(
            ActionRequest(
                action=ActionType.ESCALATE,
                target=det.asset_id,
                reason="Human review",
                auto_approved=False,
            )
        )
    else:
        actions.append(
            ActionRequest(
                action=ActionType.ALERT_ONLY,
                target=det.asset_id,
                reason="Low/medium — alert only",
                auto_approved=True,
            )
        )
    return actions


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "decision-service",
        "protection_mode": PROTECTION_MODE,
        "version": "1.5.0-tier1",
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/v1/protection")
async def get_protection():
    return {
        "protection_mode": PROTECTION_MODE,
        "description": "true = enforce actions when approved; false = detect only",
    }


@app.post("/v1/protection")
async def set_protection(payload: dict):
    global PROTECTION_MODE
    if "protection_mode" in payload:
        PROTECTION_MODE = bool(payload["protection_mode"])
    return {"protection_mode": PROTECTION_MODE}


@app.post("/v1/decide")
async def decide(det: Detection, background_tasks: BackgroundTasks):
    logger.info("Received detection %s from %s on %s", det.detection_id, det.source, det.asset_id)
    score = risk_score(det.severity, det.confidence)
    actions = plan_actions(det)
    pb = match_playbook(det.title, det.tags)
    decision_id = str(uuid.uuid4())
    matched_tags = []
    matched_title = []
    if pb:
        tagset = {str(t).lower() for t in (det.tags or [])}
        matched_tags = [t for t in pb.get("match_tags") or [] if t in tagset]
        title_l = (det.title or "").lower()
        matched_title = [m for m in pb.get("match_title") or [] if m in title_l]
    evidence = {
        "risk_score": score,
        "confidence": det.confidence,
        "severity": det.severity.value,
        "matched_playbook": pb["id"] if pb else None,
        "matched_tags": matched_tags,
        "matched_title_terms": matched_title,
        "indicators": det.indicators or {},
        "summary": (
            f"Playbook '{pb['name']}' matched via "
            + (
                ("tags " + ",".join(matched_tags))
                if matched_tags
                else ("title terms " + ",".join(matched_title))
                if matched_title
                else "heuristics"
            )
            if pb
            else f"Heuristic response for {det.severity.value} severity"
        ),
    }
    result = {
        "decision_id": decision_id,
        "detection_id": det.detection_id,
        "asset_id": det.asset_id,
        "risk_score": score,
        "confidence": det.confidence,
        "severity": det.severity.value,
        "title": det.title,
        "actions": [
            {
                "action": a.action.value,
                "target": a.target,
                "auto_approved": a.auto_approved,
                "reason": a.reason,
                "parameters": a.parameters,
            }
            for a in actions
        ],
        "requires_human": any(not a.auto_approved for a in actions),
        "protection_mode": PROTECTION_MODE,
        "playbook": (
            {
                "playbook_id": pb["id"],
                "playbook_name": pb["name"],
                "analyst_notes": pb.get("analyst_notes"),
            }
            if pb
            else None
        ),
        "evidence": evidence,
        "timestamp": time.time(),
    }
    decisions_db[decision_id] = result
    for a in actions:
        if a.auto_approved and a.action != ActionType.ALERT_ONLY:
            background_tasks.add_task(execute_action_stub, decision_id, a)
    return result


@app.get("/v1/decisions/{decision_id}")
async def get_decision(decision_id: str):
    if decision_id not in decisions_db:
        raise HTTPException(404, "Decision not found")
    return decisions_db[decision_id]


@app.get("/v1/decisions/recent")
async def recent_decisions(limit: int = 20):
    items = list(decisions_db.values())[-limit:]
    items.reverse()
    return {"count": len(items), "items": items}


@app.post("/v1/execute")
async def execute(action: ActionRequest):
    """Called after human gate approval or auto-remediate — agent executes on host."""
    logger.info("[EXECUTE] action=%s target=%s", action.action.value, action.target)
    rec = {
        "action": action.action.value,
        "target": action.target,
        "status": "dispatched",
        "message": f"Dispatched {action.action.value} on {action.target} (agent executes on host)",
        "protection_mode": PROTECTION_MODE,
        "timestamp": time.time(),
    }
    action_history.append(rec)
    return rec


async def execute_action_stub(decision_id: str, action: ActionRequest):
    logger.info(
        "[EXECUTE] decision=%s action=%s target=%s",
        decision_id,
        action.action.value,
        action.target,
    )
    action_history.append(
        {
            "decision_id": decision_id,
            "action": action.action.value,
            "target": action.target,
            "status": "dispatched",
            "timestamp": time.time(),
        }
    )


@app.get("/v1/actions/history")
async def actions_history(limit: int = 50):
    return {"count": len(action_history[-limit:]), "items": action_history[-limit:]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
