from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "weekly_client_pdf.py"
spec = importlib.util.spec_from_file_location("cg_weekly_client_pdf_test", MODULE)
reports = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = reports
spec.loader.exec_module(reports)


class FakeResponse:
    status = 200

    def __init__(self, body: bytes):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_weekly_report_request_is_tenant_scoped():
    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["tenant"] = request.get_header("X-tenant-id")
        seen["timeout"] = timeout
        return FakeResponse(b"weekly data")

    with patch.object(reports.urllib.request, "urlopen", fake_urlopen):
        result = reports.fetch_weekly("http://localhost:8080", "key", "client-a")
    assert result == "weekly data"
    assert "tenant_id=client-a" in seen["url"]
    assert seen["tenant"] == "client-a"
    assert seen["timeout"] == 15


def test_scorecard_rejects_wrong_tenant():
    body = json.dumps({"tenant_id": "client-b", "status": "ok"}).encode()
    with patch.object(reports.urllib.request, "urlopen", lambda request, timeout: FakeResponse(body)):
        try:
            reports.fetch_scorecard("http://localhost:8080", "key", "client-a")
        except RuntimeError as exc:
            assert "tenant does not match" in str(exc)
        else:
            raise AssertionError("cross-tenant scorecard must be rejected")


def test_report_cli_requires_tenant_before_network_access(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["weekly_client_pdf.py", "--key", "admin-key"])
    try:
        reports.main()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("report generation without tenant must fail closed")
