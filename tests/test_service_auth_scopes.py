from __future__ import annotations

import sys
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1] / "control-plane" / "api"
sys.path.insert(0, str(API_DIR))
from service_auth import dashboard_scope_allows, nad_scope_allows


def test_dashboard_scope_allows_only_documented_dashboard_routes():
    assert dashboard_scope_allows("GET", "/v1/fleet")
    assert dashboard_scope_allows("POST", "/v1/gate/approve/action-7")
    assert dashboard_scope_allows("POST", "/v1/gate/reject/action-7")
    assert dashboard_scope_allows("POST", "/v1/rollback/asset-9")
    assert dashboard_scope_allows("POST", "/v1/feedback/benign")
    assert not dashboard_scope_allows("POST", "/v1/agent/commands")
    assert not dashboard_scope_allows("POST", "/v1/assets/register")
    assert not dashboard_scope_allows("GET", "/v1/credentials")
    assert not dashboard_scope_allows("DELETE", "/v1/fleet")
    assert not dashboard_scope_allows("POST", "/v1/rollback/../other")


def test_nad_scope_is_detection_submission_only():
    assert nad_scope_allows("POST", "/v1/detections")
    assert not nad_scope_allows("GET", "/v1/detections")
    assert not nad_scope_allows("POST", "/v1/gate/approve/action-7")
    assert not nad_scope_allows("GET", "/v1/fleet")
