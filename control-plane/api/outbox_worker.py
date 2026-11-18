"""Supervised, bounded-retry dispatcher for CyberGuardian's durable audit outbox.

This worker delivers committed audit events only. It never executes or retries
remote agent/device commands. Delivery is at-least-once; the configured sink
must deduplicate stable event IDs.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from outbox_audit_sink import make_audit_ledger_sink
from transactional_outbox import OutboxLeaseLost, SQLiteTransactionalOutbox


class OutboxDispatcher:
    """Single-process supervised worker with leases and bounded backoff."""

    def __init__(
        self,
        store: SQLiteTransactionalOutbox,
        sink: Callable[[str, dict], None],
        *,
        worker_id: str,
        lease_seconds: float = 30.0,
        max_attempts: int = 8,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not str(worker_id).strip():
            raise ValueError("worker_id is required")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        if base_backoff_seconds <= 0 or max_backoff_seconds < base_backoff_seconds:
            raise ValueError("backoff bounds must be positive and max >= base")
        self.store = store
        self.sink = sink
        self.worker_id = str(worker_id).strip()
        self.lease_seconds = float(lease_seconds)
        self.max_attempts = int(max_attempts)
        self.base_backoff_seconds = float(base_backoff_seconds)
        self.max_backoff_seconds = float(max_backoff_seconds)
        self.clock = clock
        self.started_at = self.clock()
        self.last_attempt_at: float | None = None
        self.last_success_at: float | None = None
        self.last_error: str | None = None
        self.delivered_total = 0
        self.retry_total = 0
        self.review_total = 0

    def _backoff(self, attempt: int) -> float:
        exponent = max(0, int(attempt) - 1)
        return min(
            self.max_backoff_seconds,
            self.base_backoff_seconds * (2 ** min(exponent, 30)),
        )

    def dispatch_once(self) -> str:
        """Process at most one event; return a stable outcome label."""
        now = self.clock()
        event = self.store.claim_next(
            worker_id=self.worker_id, lease_seconds=self.lease_seconds, now=now
        )
        if event is None:
            return "idle"

        self.last_attempt_at = now
        try:
            self.sink(event["event_id"], event["payload"])
        except Exception as exc:
            # Do not expose event payloads or tenant data in worker logs.
            safe_error = f"{type(exc).__name__}: {str(exc)}"[:1000]
            try:
                outcome = self.store.retry_or_review(
                    event_id=event["event_id"],
                    worker_id=self.worker_id,
                    error=safe_error,
                    max_attempts=self.max_attempts,
                    delay_seconds=self._backoff(event["attempts"]),
                    now=self.clock(),
                )
            except OutboxLeaseLost:
                self.last_error = "lease lost while recording delivery failure"
                return "lease_lost"
            self.last_error = safe_error
            if outcome == "review_required":
                self.review_total += 1
                return "review_required"
            self.retry_total += 1
            return "retry_scheduled"

        try:
            self.store.acknowledge(
                event_id=event["event_id"],
                worker_id=self.worker_id,
                now=self.clock(),
            )
        except OutboxLeaseLost:
            # Sink may already have accepted it. Let lease recovery redeliver
            # the same stable event ID; the sink must deduplicate it.
            self.last_error = "lease lost after sink accepted event; safe replay required"
            return "lease_lost"

        self.last_success_at = self.clock()
        self.last_error = None
        self.delivered_total += 1
        return "delivered"

    def health(self) -> dict:
        metrics = self.store.queue_metrics(now=self.clock())
        return {
            "worker_id": self.worker_id,
            "status": (
                "review_required" if metrics["review_alert"]
                else "degraded" if self.last_error
                else "healthy"
            ),
            "started_at": self.started_at,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
            "delivered_by_this_worker": self.delivered_total,
            "retries_by_this_worker": self.retry_total,
            "review_escalations_by_this_worker": self.review_total,
            **metrics,
        }

    def run_forever(
        self,
        stop_event: threading.Event,
        *,
        poll_interval: float = 2.0,
        health_interval: float = 30.0,
        on_health: Callable[[dict], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if poll_interval <= 0 or health_interval <= 0:
            raise ValueError("poll and health intervals must be positive")
        next_health = self.clock()
        while not stop_event.is_set():
            try:
                outcome = self.dispatch_once()
                if outcome == "idle":
                    stop_event.wait(poll_interval)
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {str(exc)}"[:1000]
                if on_error:
                    on_error(exc)
                stop_event.wait(poll_interval)

            now = self.clock()
            if on_health and now >= next_health:
                on_health(self.health())
                next_health = now + health_interval


def _json_log(level: int, message: str, **fields) -> None:
    logging.log(level, json.dumps(
        {"message": message, **fields}, sort_keys=True, default=str
    ))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CyberGuardian supervised outbox audit dispatcher")
    parser.add_argument("--database", required=True, help="CyberGuardian SQLite database path")
    parser.add_argument("--ledger", required=True, help="Hash-chained audit ledger path")
    parser.add_argument("--worker-id", default=None, help="Stable worker identity; generated if omitted")
    parser.add_argument("--lease-seconds", type=float, default=30.0)
    parser.add_argument("--max-attempts", type=int, default=8)
    parser.add_argument("--base-backoff-seconds", type=float, default=1.0)
    parser.add_argument("--max-backoff-seconds", type=float, default=300.0)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--health-interval", type=float, default=30.0)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--once", action="store_true", help="Process at most one event and exit")
    modes.add_argument("--health-once", action="store_true", help="Print queue/worker health and exit")
    modes.add_argument("--review-queue", action="store_true", help="Print the read-only operator review queue")
    parser.add_argument("--review-limit", type=int, default=100)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    database = Path(args.database).expanduser()
    ledger = Path(args.ledger).expanduser()
    if not database.is_absolute() or not ledger.is_absolute():
        parser.error("--database and --ledger must be absolute paths")

    store = SQLiteTransactionalOutbox(database)
    worker_id = args.worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:12]}"
    dispatcher = OutboxDispatcher(
        store,
        make_audit_ledger_sink(ledger),
        worker_id=worker_id,
        lease_seconds=args.lease_seconds,
        max_attempts=args.max_attempts,
        base_backoff_seconds=args.base_backoff_seconds,
        max_backoff_seconds=args.max_backoff_seconds,
    )

    if args.health_once:
        health = dispatcher.health()
        print(json.dumps(health, sort_keys=True))
        return 2 if health["review_alert"] else 0

    if args.review_queue:
        print(json.dumps(store.review_queue(limit=args.review_limit), sort_keys=True))
        return 0

    if args.once:
        outcome = dispatcher.dispatch_once()
        print(json.dumps({"outcome": outcome, **dispatcher.health()}, sort_keys=True))
        return 2 if outcome in {"review_required", "lease_lost"} else 0

    stop_event = threading.Event()

    def request_stop(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    _json_log(logging.INFO, "outbox worker started", worker_id=worker_id)

    dispatcher.run_forever(
        stop_event,
        poll_interval=args.poll_interval,
        health_interval=args.health_interval,
        on_health=lambda health: _json_log(logging.INFO, "outbox worker health", **health),
        on_error=lambda exc: _json_log(
            logging.ERROR, "outbox worker loop error",
            error_type=type(exc).__name__, error=str(exc)[:1000],
        ),
    )
    _json_log(logging.INFO, "outbox worker stopped", **dispatcher.health())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
