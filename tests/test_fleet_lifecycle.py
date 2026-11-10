from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "control-plane" / "api" / "fleet_lifecycle.py"
spec = importlib.util.spec_from_file_location("cg_fleet_lifecycle_test", MODULE)
fleet = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fleet
spec.loader.exec_module(fleet)


def test_last_seen_projects_online_and_offline_states():
    result = fleet.project_fleet_lifecycle(
        [
            {"asset_id": "fresh", "status": "online", "last_seen": 990},
            {"asset_id": "stale", "status": "online", "last_seen": 900},
        ],
        now=1000,
        stale_after_seconds=60,
    )
    assert result[0]["lifecycle"] == "online"
    assert result[0]["status"] == "online"
    assert result[0]["stale"] is False
    assert result[1]["lifecycle"] == "offline"
    assert result[1]["status"] == "offline"
    assert result[1]["stale"] is True


def test_unknown_timestamp_and_revoked_state_are_not_marked_online():
    result = fleet.project_fleet_lifecycle(
        [
            {"asset_id": "unknown", "status": "online", "last_seen": None},
            {"asset_id": "revoked", "status": "revoked", "last_seen": 999},
        ],
        now=1000,
        stale_after_seconds=60,
    )
    assert result[0]["lifecycle"] == "unknown"
    assert result[0]["status"] == "unknown"
    assert result[0]["stale"] is True
    assert result[1]["lifecycle"] == "revoked"
    assert result[1]["status"] == "revoked"


def test_fleet_projection_does_not_mutate_source_records():
    source = [{"asset_id": "a", "status": "online", "last_seen": 0}]
    projected = fleet.project_fleet_lifecycle(source, now=1000, stale_after_seconds=30)
    assert source[0]["status"] == "online"
    assert projected[0]["status"] == "offline"



def test_revoked_and_disabled_states_survive_missing_heartbeat_timestamps():
    result = fleet.project_fleet_lifecycle(
        [
            {"asset_id": "revoked-no-heartbeat", "status": "revoked", "last_seen": None},
            {"asset_id": "disabled-no-heartbeat", "status": "disabled", "last_seen": None},
        ],
        now=1000,
        stale_after_seconds=60,
    )
    assert result[0]["lifecycle"] == "revoked"
    assert result[0]["status"] == "revoked"
    assert result[1]["lifecycle"] == "disabled"
    assert result[1]["status"] == "disabled"
