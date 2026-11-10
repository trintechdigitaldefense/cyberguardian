"""Deterministic patch: authenticate API-gateway calls to the decision service."""
from __future__ import annotations

import re

PATCH_MARKER = "# CYBERGUARDIAN_PATCH: decision_service_auth_v1"


def patch_source(source: str) -> str:
    if PATCH_MARKER in source:
        return source

    anchor = 'DECISION_URL = os.getenv("DECISION_SERVICE_URL", "http://127.0.0.1:8001")'
    if source.count(anchor) != 1:
        raise ValueError("decision-service URL anchor missing or ambiguous")
    helper = anchor + '''

# CYBERGUARDIAN_PATCH: decision_service_auth_v1
DECISION_SERVICE_API_KEY = os.getenv("DECISION_SERVICE_API_KEY", "").strip()


def decision_service_headers() -> dict:
    if not DECISION_SERVICE_API_KEY:
        if os.getenv("CG_PRODUCTION", "0").strip().lower() in {"1", "true", "yes", "on"}:
            raise HTTPException(503, "Decision-service authentication is not configured")
        return {}
    return {"X-Decision-Service-Key": DECISION_SERVICE_API_KEY}
'''
    source = source.replace(anchor, helper, 1)

    decide_old = 'resp = await client.post(f"{DECISION_URL}/v1/decide", json=detection)'
    decide_new = 'resp = await client.post(f"{DECISION_URL}/v1/decide", json=detection, headers=decision_service_headers())'
    if source.count(decide_old) != 1:
        raise ValueError("decision endpoint call anchor missing or ambiguous")
    source = source.replace(decide_old, decide_new, 1)

    execute_pattern = r'(?m)^(\s*)f"\{DECISION_URL\}/v1/execute",\s*$'
    def add_auth(match: re.Match) -> str:
        indent = match.group(1)
        return match.group(0) + "\n" + indent + "    headers=decision_service_headers(),"

    source, count = re.subn(execute_pattern, add_auth, source)
    if count != 2:
        raise ValueError(f"expected 2 decision execute call sites, found {count}")
    return source
