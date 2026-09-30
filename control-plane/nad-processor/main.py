"""NAD Processor — anomaly simulation helpers for pilot/testing."""
from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import httpx, os

app = FastAPI(title="CyberGuardian NAD", version="1.0.0-detect")
API_URL = os.getenv("API_URL", "http://127.0.0.1:8080")
API_KEY = os.getenv("CYBERGUARDIAN_API_KEY", "")

class SimulatedAnomaly(BaseModel):
    asset_id: str
    anomaly_type: str = "suspicious_process"

TEMPLATES = {
    "suspicious_process": {
        "severity": "high", "confidence": 0.88,
        "title": "Suspicious process: mimikatz",
        "description": "Credential access tool pattern",
        "indicators": {"pid": "9999"}, "tags": ["credential_access", "suspicious_process"],
    },
    "ransomware": {
        "severity": "critical", "confidence": 0.95,
        "title": "Ransomware indicator - mass file encryption",
        "description": "High rate of file renames",
        "indicators": {"extension": ".locked"}, "tags": ["ransomware", "impact"],
    },
    "c2": {
        "severity": "high", "confidence": 0.8,
        "title": "Periodic outbound beacon",
        "description": "C2-style connection pattern",
        "indicators": {"dst_ip": "185.220.101.45"}, "tags": ["c2", "beacon"],
    },
    "credential_dump": {
        "severity": "critical", "confidence": 0.94,
        "title": "Credential dump attempt",
        "description": "LSASS / SAM access pattern",
        "indicators": {"cmdline": "sekurlsa::logonpasswords"}, "tags": ["credential_access"],
    },
}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "nad-processor", "version": "1.0.0-detect", "time": datetime.now(timezone.utc).isoformat()}

async def emit(asset_id: str, anomaly: dict):
    payload = {"source": "nad-processor", "asset_id": asset_id, **anomaly}
    headers = {"X-API-Key": API_KEY} if API_KEY else {}
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            await c.post(f"{API_URL}/v1/detections", json=payload, headers=headers)
    except Exception:
        pass

@app.post("/v1/simulate")
async def simulate(payload: SimulatedAnomaly, background_tasks: BackgroundTasks):
    anomaly = TEMPLATES.get(payload.anomaly_type, TEMPLATES["suspicious_process"])
    background_tasks.add_task(emit, payload.asset_id, anomaly)
    return {"status": "simulated", "anomaly": anomaly}
