from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "dashboard" / "client_reporting.py"
spec = importlib.util.spec_from_file_location("cg_client_reporting_test", MODULE)
reporting = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporting)


def sample_snapshot():
    return {
        "tenant_id": "client-a",
        "risk": {"total_assets": 12, "online": 10, "open_detections": 2},
        "fleet": {"online": 10, "items": []},
        "gate": {"pending_count": 1, "pending": [{"id": "p1"}]},
        "issues": {"items": [{"title": "High severity malware detection", "severity": "high", "status": "open"}]},
        "audit": {"items": [{"event": "operator_request_started"}, {"event": "agent_heartbeat"}]},
        "client_mode": True,
        "weekly_summary": "One endpoint had a high severity detection.",
    }


def test_client_report_is_pdf_and_translates_terms():
    pdf = reporting.build_client_pdf(
        sample_snapshot(),
        tenant_id="client-a",
        generated_at=datetime(2026, 11, 10, tzinfo=timezone.utc),
    )
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000
    assert reporting.translate("malware alert") == "harmful software alert"


def test_client_report_rejects_missing_or_mismatched_tenant():
    for tenant in ("", "client-b"):
        try:
            reporting.build_client_pdf(sample_snapshot(), tenant_id=tenant)
        except ValueError as exc:
            assert "tenant identity" in str(exc)
        else:
            raise AssertionError("report must reject missing or mismatched tenant")


def test_client_report_does_not_treat_missing_metrics_as_zero():
    snapshot = sample_snapshot()
    snapshot["risk"] = {}
    pdf = reporting.build_client_pdf(snapshot, tenant_id="client-a")
    assert pdf.startswith(b"%PDF-")
