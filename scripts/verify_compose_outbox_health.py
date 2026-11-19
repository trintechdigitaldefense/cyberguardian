#!/usr/bin/env python3
"""Require the Compose outbox worker to remain healthy across real health checks.

This verifies Docker Compose supervision in an isolated test stack. It is not
a substitute for physical power, network, storage, multi-device, or recovery
drills on the intended deployment environment.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _timestamp(value: Any) -> float | None:
    """Parse Docker's RFC3339 health-log timestamp into Unix seconds."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def observation_health(
    snapshot: dict[str, Any], observed_after: float
) -> tuple[bool, str, list[dict[str, Any]]]:
    """Return running state, health status, and check results in the window."""
    state = snapshot.get("State") or {}
    health = state.get("Health") or {}
    status = str(health.get("Status") or "missing")
    checks: list[dict[str, Any]] = []
    for item in health.get("Log") or []:
        ended = _timestamp(item.get("End"))
        if ended is None or ended < observed_after:
            continue
        try:
            exit_code = int(item.get("ExitCode"))
        except (TypeError, ValueError):
            exit_code = 255
        checks.append({"end": item.get("End"), "exit_code": exit_code})
    return state.get("Running") is True, status, checks


def _run(command: list[str], *, cwd: Path) -> str:
    try:
        result = subprocess.run(
            command, cwd=cwd, text=True, capture_output=True, check=False
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"required executable not found: {command[0]}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no command output").strip()
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}: {detail}"
        )
    return result.stdout.strip()


def _inspect(container_id: str, *, cwd: Path) -> dict[str, Any]:
    raw = _run(["docker", "inspect", container_id], cwd=cwd)
    try:
        records = json.loads(raw)
        return records[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise RuntimeError("docker inspect returned an invalid container record") from exc


def _diagnostic(snapshot: dict[str, Any]) -> str:
    state = snapshot.get("State") or {}
    health = state.get("Health") or {}
    recent = [
        {
            "end": item.get("End"),
            "exit_code": item.get("ExitCode"),
            "output": str(item.get("Output") or "")[:300],
        }
        for item in (health.get("Log") or [])[-5:]
    ]
    return json.dumps(
        {
            "container_status": state.get("Status"),
            "running": state.get("Running"),
            "health_status": health.get("Status", "missing"),
            "recent_health_checks": recent,
        },
        sort_keys=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Wait for sustained healthy status of the Compose outbox-worker"
    )
    parser.add_argument(
        "--project",
        default=os.environ.get("COMPOSE_PROJECT_NAME", "cg-compose-ci"),
        help="Compose project name used to start the stack",
    )
    parser.add_argument(
        "--compose-file",
        default=str(ROOT / "deploy" / "docker" / "docker-compose.yml"),
        help="Path to the Compose file",
    )
    parser.add_argument("--start-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--observe-seconds", type=float, default=70.0)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--min-successful-checks", type=int, default=2)
    args = parser.parse_args(argv)

    if (
        args.start_timeout_seconds <= 0
        or args.observe_seconds <= 0
        or args.poll_seconds <= 0
        or args.min_successful_checks < 1
    ):
        parser.error("timeouts/poll interval must be positive and minimum checks >= 1")

    compose_file = Path(args.compose_file).expanduser().resolve()
    if not compose_file.is_file():
        parser.error(f"Compose file does not exist: {compose_file}")

    compose = [
        "docker",
        "compose",
        "--project-name",
        args.project,
        "--file",
        str(compose_file),
    ]
    try:
        container_ids = _run(
            compose + ["ps", "-q", "outbox-worker"], cwd=ROOT
        ).split()
        if len(container_ids) != 1:
            raise RuntimeError(
                "expected exactly one outbox-worker container; "
                f"found {len(container_ids)}"
            )
        container_id = container_ids[0]

        start_deadline = time.monotonic() + args.start_timeout_seconds
        latest = _inspect(container_id, cwd=ROOT)
        while True:
            running, status, _ = observation_health(latest, float("inf"))
            if status == "unhealthy":
                raise RuntimeError(
                    "outbox-worker became unhealthy before observation: "
                    + _diagnostic(latest)
                )
            if running and status == "healthy":
                break
            if not running:
                raise RuntimeError(
                    "outbox-worker stopped before becoming healthy: "
                    + _diagnostic(latest)
                )
            if time.monotonic() >= start_deadline:
                raise RuntimeError(
                    "timed out waiting for outbox-worker health=healthy: "
                    + _diagnostic(latest)
                )
            time.sleep(args.poll_seconds)
            latest = _inspect(container_id, cwd=ROOT)

        first_healthy_at = datetime.now(timezone.utc).isoformat()
        observation_started = time.time()
        observation_deadline = time.monotonic() + args.observe_seconds

        while True:
            latest = _inspect(container_id, cwd=ROOT)
            running, status, checks = observation_health(
                latest, observation_started
            )
            if not running or status != "healthy":
                raise RuntimeError(
                    "outbox-worker lost healthy/running state during observation: "
                    + _diagnostic(latest)
                )
            failures = [item for item in checks if item["exit_code"] != 0]
            if failures:
                raise RuntimeError(
                    "a Docker health check failed during the observation window: "
                    + _diagnostic(latest)
                )
            if time.monotonic() >= observation_deadline:
                break
            time.sleep(min(args.poll_seconds, max(
                0.0, observation_deadline - time.monotonic()
            )))

        latest = _inspect(container_id, cwd=ROOT)
        running, status, checks = observation_health(latest, observation_started)
        successes = [item for item in checks if item["exit_code"] == 0]
        failures = [item for item in checks if item["exit_code"] != 0]
        if not running or status != "healthy" or failures:
            raise RuntimeError(
                "final Compose health state was not healthy: " + _diagnostic(latest)
            )
        if len(successes) < args.min_successful_checks:
            raise RuntimeError(
                "insufficient successful Docker health checks in observation window: "
                f"expected at least {args.min_successful_checks}, got {len(successes)}; "
                + _diagnostic(latest)
            )

        evidence = {
            "service": "outbox-worker",
            "container_id": container_id[:12],
            "compose_project": args.project,
            "health_status": status,
            "running": running,
            "observation_seconds": round(time.time() - observation_started, 1),
            "successful_health_checks_in_window": len(successes),
            "failed_health_checks_in_window": len(failures),
            "first_healthy_at_utc": first_healthy_at,
            "observation_started_at_utc": datetime.fromtimestamp(
                observation_started, timezone.utc
            ).isoformat(),
            "health_check_ends_utc": [item["end"] for item in successes],
        }
        print(json.dumps(evidence, sort_keys=True))
        return 0
    except (RuntimeError, OSError) as exc:
        print(f"OUTBOX COMPOSE HEALTH VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
