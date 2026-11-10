from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
NAD_DIR = ROOT / "control-plane" / "nad-processor"


def _load_nad_module():
    spec = importlib.util.spec_from_file_location(
        "cg_nad_service_security_test_module", NAD_DIR / "main.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_production_nad_disables_synthetic_detection_endpoint(monkeypatch):
    nad = _load_nad_module()
    monkeypatch.setattr(nad, "PRODUCTION", True)
    client = TestClient(nad.app)
    response = client.post(
        "/v1/simulate",
        json={"asset_id": "test-asset", "anomaly_type": "suspicious_process"},
    )
    assert response.status_code == 404
    assert "disabled in production" in response.json()["detail"]


def test_production_nad_refuses_startup_without_outbound_service_key(monkeypatch):
    nad = _load_nad_module()
    monkeypatch.setattr(nad, "PRODUCTION", True)
    monkeypatch.setattr(nad, "API_KEY", "")
    try:
        with TestClient(nad.app):
            pass
    except RuntimeError as exc:
        assert "production NAD service credential" in str(exc)
    else:
        raise AssertionError("production NAD must not start without its outbound service key")
