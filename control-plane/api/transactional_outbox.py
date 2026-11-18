"""SQLite transactional operation registry and durable outbox.

The operation callback MUST confine business-state mutations to the supplied
SQLite connection. External side effects require a downstream idempotency key
and reconciliation; SQLite cannot atomically commit a remote side effect.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


class IdempotencyConflict(ValueError):
    """An idempotency key was reused for a different request."""


class OutboxLeaseLost(RuntimeError):
    """A worker attempted to acknowledge an event it no longer owns."""


@dataclass(frozen=True)
class OperationResult:
    operation_id: str
    status: str
    result: Any
    replayed: bool


class SQLiteTransactionalOutbox:
    """Atomic SQLite operations plus ordered, at-least-once outbox delivery."""

    def __init__(self, database_path: str | Path, *, busy_timeout_ms: int = 30000):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.busy_timeout_ms = int(busy_timeout_ms)
        if self.busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be positive")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path), timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS cg_operations (
                    operation_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('completed')),
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(tenant_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS cg_outbox (
                    event_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL REFERENCES cg_operations(operation_id),
                    tenant_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending', 'inflight', 'delivered')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL,
                    lease_owner TEXT,
                    lease_until REAL,
                    last_error TEXT,
                    created_at REAL NOT NULL,
                    delivered_at REAL,
                    UNIQUE(operation_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS idx_cg_outbox_ready
                    ON cg_outbox(status, next_attempt_at, created_at);
                CREATE INDEX IF NOT EXISTS idx_cg_outbox_operation_order
                    ON cg_outbox(operation_id, sequence, status);
            """)

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def execute_operation(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        request_hash: str,
        handler: Callable[[sqlite3.Connection, str], Any],
        now: float | None = None,
    ) -> OperationResult:
        """Commit business writes, operation result, and both outbox events atomically.

        Handler code must use the supplied connection for all business writes.
        Raising (including injected process-failure exceptions) rolls back all
        writes and leaves no misleading completed operation or outbox event.
        """
        tenant_id = str(tenant_id).strip()
        idempotency_key = str(idempotency_key).strip()
        request_hash = str(request_hash).strip()
        if not tenant_id or not idempotency_key or not request_hash:
            raise ValueError("tenant_id, idempotency_key and request_hash are required")
        if len(idempotency_key) > 256 or len(request_hash) > 256:
            raise ValueError("idempotency key or request hash is too long")
        timestamp = time.time() if now is None else float(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT operation_id, request_hash, status, result_json
                   FROM cg_operations WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if existing:
                if existing["request_hash"] != request_hash:
                    raise IdempotencyConflict("idempotency key already belongs to a different request")
                connection.commit()
                return OperationResult(
                    existing["operation_id"], existing["status"],
                    json.loads(existing["result_json"]), True,
                )

            operation_id = uuid.uuid4().hex
            connection.execute(
                """INSERT INTO cg_operations
                   (operation_id, tenant_id, idempotency_key, request_hash, status,
                    result_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'completed', 'null', ?, ?)""",
                (operation_id, tenant_id, idempotency_key, request_hash, timestamp, timestamp),
            )
            self._enqueue(
                connection, operation_id, tenant_id, 1, "operation_intent",
                {"operation_id": operation_id, "tenant_id": tenant_id,
                 "request_hash": request_hash, "phase": "accepted"}, timestamp,
            )
            result = handler(connection, operation_id)
            result_json = self._json(result)
            connection.execute(
                "UPDATE cg_operations SET result_json=?, updated_at=? WHERE operation_id=?",
                (result_json, timestamp, operation_id),
            )
            self._enqueue(
                connection, operation_id, tenant_id, 2, "operation_completed",
                {"operation_id": operation_id, "tenant_id": tenant_id,
                 "phase": "completed", "result": result}, timestamp,
            )
            connection.commit()
            return OperationResult(operation_id, "completed", json.loads(result_json), False)
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _enqueue(
        self, connection: sqlite3.Connection, operation_id: str, tenant_id: str,
        sequence: int, event_type: str, payload: dict, timestamp: float,
    ) -> str:
        event_id = uuid.uuid4().hex
        connection.execute(
            """INSERT INTO cg_outbox
               (event_id, operation_id, tenant_id, sequence, event_type,
                payload_json, status, attempts, next_attempt_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)""",
            (event_id, operation_id, tenant_id, sequence, event_type,
             self._json(payload), timestamp, timestamp),
        )
        return event_id

    def claim_next(
        self, *, worker_id: str, lease_seconds: float = 30,
        now: float | None = None,
    ) -> dict | None:
        worker_id = str(worker_id).strip()
        if not worker_id or lease_seconds <= 0:
            raise ValueError("worker_id and positive lease_seconds are required")
        timestamp = time.time() if now is None else float(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT o.* FROM cg_outbox AS o
                   WHERE ((o.status='pending' AND o.next_attempt_at<=?)
                       OR (o.status='inflight' AND o.lease_until<=?))
                     AND NOT EXISTS (
                       SELECT 1 FROM cg_outbox AS earlier
                       WHERE earlier.operation_id=o.operation_id
                         AND earlier.sequence<o.sequence
                         AND earlier.status!='delivered'
                     )
                   ORDER BY o.created_at, o.operation_id, o.sequence
                   LIMIT 1""",
                (timestamp, timestamp),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            connection.execute(
                """UPDATE cg_outbox SET status='inflight', lease_owner=?,
                   lease_until=?, attempts=attempts+1
                   WHERE event_id=?""",
                (worker_id, timestamp + lease_seconds, row["event_id"]),
            )
            claimed = dict(row)
            claimed.update(status="inflight", lease_owner=worker_id,
                           lease_until=timestamp + lease_seconds,
                           attempts=int(row["attempts"]) + 1)
            claimed["payload"] = json.loads(claimed.pop("payload_json"))
            connection.commit()
            return claimed
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def acknowledge(self, *, event_id: str, worker_id: str, now: float | None = None) -> None:
        timestamp = time.time() if now is None else float(now)
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE cg_outbox SET status='delivered', delivered_at=?,
                   lease_owner=NULL, lease_until=NULL, last_error=NULL
                   WHERE event_id=? AND status='inflight' AND lease_owner=?
                     AND lease_until>?""",
                (timestamp, event_id, worker_id, timestamp),
            )
            if cursor.rowcount != 1:
                raise OutboxLeaseLost("outbox event is not leased by this worker")

    def retry(
        self, *, event_id: str, worker_id: str, error: str,
        delay_seconds: float, now: float | None = None,
    ) -> None:
        timestamp = time.time() if now is None else float(now)
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE cg_outbox SET status='pending', next_attempt_at=?,
                   lease_owner=NULL, lease_until=NULL, last_error=?
                   WHERE event_id=? AND status='inflight' AND lease_owner=?
                     AND lease_until>?""",
                (timestamp + max(0.0, float(delay_seconds)), str(error)[:1000],
                 event_id, worker_id, timestamp),
            )
            if cursor.rowcount != 1:
                raise OutboxLeaseLost("outbox event is not leased by this worker")

    def dispatch_once(
        self, *, worker_id: str, sink: Callable[[str, dict], None],
        lease_seconds: float = 30, retry_delay: float = 5,
        now: float | None = None,
    ) -> bool:
        """Deliver one event at least once; sink must deduplicate by event_id."""
        timestamp = time.time() if now is None else float(now)
        event = self.claim_next(worker_id=worker_id, lease_seconds=lease_seconds, now=timestamp)
        if event is None:
            return False
        try:
            sink(event["event_id"], event["payload"])
        except Exception as exc:
            self.retry(event_id=event["event_id"], worker_id=worker_id,
                       error=str(exc), delay_seconds=retry_delay, now=timestamp)
            return True
        self.acknowledge(event_id=event["event_id"], worker_id=worker_id, now=timestamp)
        return True

    def operation(self, *, tenant_id: str, operation_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT operation_id, tenant_id, idempotency_key, request_hash,
                          status, result_json, created_at, updated_at
                   FROM cg_operations WHERE tenant_id=? AND operation_id=?""",
                (tenant_id, operation_id),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["result"] = json.loads(result.pop("result_json"))
        return result

    def outbox_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM cg_outbox GROUP BY status"
            ).fetchall()
        counts = {"pending": 0, "inflight": 0, "delivered": 0}
        counts.update({row["status"]: int(row["count"]) for row in rows})
        return counts
