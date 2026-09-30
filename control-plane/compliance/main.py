from datetime import datetime, timezone
from fastapi import FastAPI
app = FastAPI(title="CyberGuardian Compliance", version="0.1.0")
@app.get("/health")
async def health():
    return {"status": "ok", "service": "compliance", "time": datetime.now(timezone.utc).isoformat()}
@app.get("/v1/summary")
async def summary():
    return {
        "frameworks": {
            "CIS": {"total": 5, "passing": 5, "gaps": 0, "score": 100},
            "HIPAA": {"total": 6, "passing": 5, "gaps": 1, "score": 83},
            "SOC2": {"total": 6, "passing": 5, "gaps": 1, "score": 83},
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
