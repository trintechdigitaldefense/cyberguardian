from datetime import datetime, timezone
from fastapi import FastAPI
app = FastAPI(title="CyberGuardian TIE", version="0.1.0")
THREATS = [
    {"ioc": "185.220.101.45", "type": "ip", "threat_type": "c2", "severity": "high", "confidence": 0.9, "description": "Known C2 / Tor exit node", "tags": ["c2", "tor"]},
    {"ioc": "mimikatz", "type": "tool", "threat_type": "credential_access", "severity": "critical", "confidence": 0.99, "description": "Credential dumping tool", "tags": ["credential_access"]},
]
@app.get("/health")
async def health():
    return {"status": "ok", "service": "tie", "time": datetime.now(timezone.utc).isoformat()}
@app.get("/v1/threats")
async def threats():
    return {"count": len(THREATS), "items": THREATS}
