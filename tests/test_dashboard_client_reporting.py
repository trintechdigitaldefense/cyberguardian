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



def historical_snapshot():
    snapshot = sample_snapshot()
    snapshot["audit"] = {"tenant_id": "client-a", "items": [
        {
            "source_record_id": "audit-record-001",
            "timestamp": "2026-11-01T00:00:00Z",
            "event": "agent_heartbeat",
            "tenant_id": "client-a",
        },
        {
            "source_record_id": "audit-record-002",
            "timestamp": "2026-11-05T12:30:00Z",
            "event": "operator_approval",
            "tenant_id": "client-a",
        },
    ]}
    return snapshot


def historical_period():
    return {
        "start": "2026-11-01T00:00:00Z",
        "end": "2026-11-10T00:00:00Z",
        "timezone": "UTC",
        "boundary": "[start, end)",
        "snapshot_head": "f" * 64,
        "source_record_count": 2,
    }


def test_historical_pdf_contains_requested_period_and_source_record_ids():
    pdf = reporting.build_client_pdf(
        historical_snapshot(),
        tenant_id="client-a",
        generated_at=datetime(2026, 11, 10, tzinfo=timezone.utc),
        report_period=historical_period(),
    )
    assert pdf.startswith(b"%PDF-")
    assert b"2026-11-01" in pdf
    assert b"audit-record-001" in pdf
    assert b"audit-record-002" in pdf


def test_historical_pdf_rejects_out_of_window_or_cross_tenant_records():
    for mutation in (
        lambda item: item.update(timestamp="2026-11-10T00:00:00Z"),
        lambda item: item.update(tenant_id="client-b"),
        lambda item: item.update(source_record_id=""),
    ):
        snapshot = historical_snapshot()
        mutation(snapshot["audit"]["items"][0])
        try:
            reporting.build_client_pdf(snapshot, tenant_id="client-a", report_period=historical_period())
        except ValueError:
            pass
        else:
            raise AssertionError("invalid historical audit provenance must be rejected")


def test_historical_pdf_rejects_duplicate_ids_and_count_mismatch():
    snapshot = historical_snapshot()
    snapshot["audit"]["items"][1]["source_record_id"] = "audit-record-001"
    try:
        reporting.build_client_pdf(snapshot, tenant_id="client-a", report_period=historical_period())
    except ValueError as exc:
        assert "duplicated" in str(exc)
    else:
        raise AssertionError("duplicate source IDs must be rejected")

    snapshot = historical_snapshot()
    period = historical_period()
    period["source_record_count"] = 99
    try:
        reporting.build_client_pdf(snapshot, tenant_id="client-a", report_period=period)
    except ValueError as exc:
        assert "count" in str(exc)
    else:
        raise AssertionError("source count mismatch must be rejected")
