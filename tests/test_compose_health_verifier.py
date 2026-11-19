"""Unit tests for the Compose outbox worker health verifier."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from verify_compose_outbox_health import observation_health  # noqa: E402


def _snapshot(status: str, entries: list[dict] | None = None) -> dict:
    return {
        "State": {
            "Running": True,
            "Status": "running",
            "Health": {"Status": status, "Log": entries or []},
        }
    }


def test_observation_counts_only_health_checks_completed_in_window():
    snapshot = _snapshot("healthy", [
        {"End": "2026-11-18T20:00:00Z", "ExitCode": 0},
        {"End": "2026-11-18T20:00:30Z", "ExitCode": 0},
        {"End": "2026-11-18T20:01:00Z", "ExitCode": 0},
    ])

    running, status, checks = observation_health(snapshot, 179.0)

    assert running is True
    assert status == "healthy"
    assert [item["exit_code"] for item in checks] == [0, 0]


def test_observation_preserves_failed_health_check_for_fail_closed_result():
    snapshot = _snapshot("healthy", [
        {"End": "2026-11-18T20:00:30Z", "ExitCode": 1},
        {"End": "2026-11-18T20:01:00Z", "ExitCode": 0},
    ])

    _, _, checks = observation_health(snapshot, 0.0)

    assert [item["exit_code"] for item in checks] == [1, 0]


def test_missing_compose_healthcheck_is_not_reported_as_healthy():
    snapshot = {"State": {"Running": True, "Status": "running"}}

    running, status, checks = observation_health(snapshot, 0.0)

    assert running is True
    assert status == "missing"
    assert checks == []


def test_stopped_worker_is_reported_as_not_running():
    snapshot = _snapshot("healthy")
    snapshot["State"]["Running"] = False

    running, status, _ = observation_health(snapshot, 0.0)

    assert running is False
    assert status == "healthy"
