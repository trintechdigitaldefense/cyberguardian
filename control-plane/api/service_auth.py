"""Default-deny endpoint scopes for internal workload identities."""
from __future__ import annotations

import re

_DASHBOARD_EXACT = {
    ("GET", "/v1/risk/summary"),
    ("GET", "/v1/fleet"),
    ("GET", "/v1/gate"),
    ("GET", "/v1/client-mode"),
    ("GET", "/v1/issues/client-view"),
    ("GET", "/v1/inventory/report"),
    ("GET", "/v1/audit"),
    ("GET", "/v1/audit/history"),
    ("GET", "/v1/pilot/scorecard"),
    ("GET", "/v1/reports/weekly"),
    ("GET", "/v1/feedback"),
    ("GET", "/v1/hardening"),
    ("POST", "/v1/client-mode"),
    ("POST", "/v1/feedback/benign"),
}
_DASHBOARD_DYNAMIC = (
    re.compile(r"^/v1/gate/(?:approve|reject)/[A-Za-z0-9_.:-]{1,128}$"),
    re.compile(r"^/v1/rollback/[A-Za-z0-9_.:-]{1,128}$"),
)


def dashboard_scope_allows(method: str, path: str) -> bool:
    verb = str(method).upper()
    route = str(path)
    if (verb, route) in _DASHBOARD_EXACT:
        return True
    return verb == "POST" and any(pattern.fullmatch(route) for pattern in _DASHBOARD_DYNAMIC)


def nad_scope_allows(method: str, path: str) -> bool:
    return str(method).upper() == "POST" and str(path) == "/v1/detections"
