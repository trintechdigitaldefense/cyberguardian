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
                    status TEXT NOT NULL CHECK(status IN ('completed', 'reconciliation_required')),
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
            self._migrate_outbox_review_status(connection)

    @staticmethod
    def _migrate_outbox_review_status(connection: sqlite3.Connection) -> None:
        """Add a durable operator-review state without discarding existing rows."""
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='cg_outbox'"
        ).fetchone()
        if schema is None or "review_required" in str(schema["sql"]):
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("DROP INDEX IF EXISTS idx_cg_outbox_ready")
            connection.execute("DROP INDEX IF EXISTS idx_cg_outbox_operation_order")
            connection.execute("ALTER TABLE cg_outbox RENAME TO cg_outbox_legacy")
            connection.execute("""
                CREATE TABLE cg_outbox (
                    event_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL REFERENCES cg_operations(operation_id),
                    tenant_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending', 'inflight', 'delivered', 'review_required')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL,
                    lease_owner TEXT,
                    lease_until REAL,
                    last_error TEXT,
                    created_at REAL NOT NULL,
                    delivered_at REAL,
                    UNIQUE(operation_id, sequence)
                )
            """)
            connection.execute("""
                INSERT INTO cg_outbox
                (event_id, operation_id, tenant_id, sequence, event_type, payload_json,
                 status, attempts, next_attempt_at, lease_owner, lease_until,
                 last_error, created_at, delivered_at)
                SELECT event_id, operation_id, tenant_id, sequence, event_type, payload_json,
                       status, attempts, next_attempt_at, lease_owner, lease_until,
                       last_error, created_at, delivered_at
                FROM cg_outbox_legacy
            """)
            connection.execute("DROP TABLE cg_outbox_legacy")
            connection.execute("""
                CREATE INDEX idx_cg_outbox_ready
                ON cg_outbox(status, next_attempt_at, created_at)
            """)
            connection.execute("""
                CREATE INDEX idx_cg_outbox_operation_order
                ON cg_outbox(operation_id, sequence, status)
            """)
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise

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

    def execute_operation_on_connection(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        idempotency_key: str,
        request_hash: str,
        handler: Callable[[sqlite3.Connection, str], Any],
        now: float | None = None,
    ) -> OperationResult:
        """Atomically execute against the caller's existing application DB connection.

        This is the live-integration path: application state and outbox rows
        must use the same SQLite database and the exact same connection. The
        caller owns connection lifetime; this method owns the transaction and
        commits only after business writes, operation metadata and outbox
        intent/completion events are all durable.
        """
        tenant_id = str(tenant_id).strip()
        idempotency_key = str(idempotency_key).strip()
        request_hash = str(request_hash).strip()
        if not tenant_id or not idempotency_key or not request_hash:
            raise ValueError("tenant_id, idempotency_key and request_hash are required")
        if len(idempotency_key) > 256 or len(request_hash) > 256:
            raise ValueError("idempotency key or request hash is too long")
        if connection.in_transaction:
            raise RuntimeError("live outbox requires ownership of a fresh transaction")
        timestamp = time.time() if now is None else float(now)
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        connection.execute("PRAGMA synchronous=FULL")
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT operation_id, request_hash, status, result_json
                   FROM cg_operations WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if existing:
                if existing["request_hash"] != request_hash:
                    raise IdempotencyConflict(
                        "idempotency key already belongs to a different request"
                    )
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
                (operation_id, tenant_id, idempotency_key, request_hash,
                 timestamp, timestamp),
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
            return OperationResult(
                operation_id, "completed", json.loads(result_json), False
            )
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise

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

    def mark_reconciliation_required(
        self, *, tenant_id: str, operation_id: str, reason: str,
        now: float | None = None,
    ) -> bool:
        """Persist an operator-reconciliation state and an ordered outbox event."""
        tenant_id = str(tenant_id).strip()
        operation_id = str(operation_id).strip()
        reason = str(reason).strip()
        if not tenant_id or not operation_id or not reason:
            raise ValueError("tenant_id, operation_id and reason are required")
        timestamp = time.time() if now is None else float(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status FROM cg_operations WHERE tenant_id=? AND operation_id=?",
                (tenant_id, operation_id),
            ).fetchone()
            if row is None:
                raise KeyError("operation not found for tenant")
            if row["status"] == "reconciliation_required":
                connection.commit()
                return False
            connection.execute(
                """UPDATE cg_operations SET status='reconciliation_required',
                   updated_at=? WHERE tenant_id=? AND operation_id=?""",
                (timestamp, tenant_id, operation_id),
            )
            sequence = int(connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM cg_outbox WHERE operation_id=?",
                (operation_id,),
            ).fetchone()[0])
            self._enqueue(
                connection, operation_id, tenant_id, sequence,
                "operation_reconciliation_required",
                {"operation_id": operation_id, "tenant_id": tenant_id,
                 "phase": "reconciliation_required", "reason": reason[:1000]},
                timestamp,
            )
            connection.commit()
            return True
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def retry_or_review(
        self, *, event_id: str, worker_id: str, error: str,
        max_attempts: int, delay_seconds: float, now: float | None = None,
    ) -> str:
        """Release a failed lease for bounded retry or move it to operator review."""
        if int(max_attempts) < 1:
            raise ValueError("max_attempts must be at least one")
        timestamp = time.time() if now is None else float(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT attempts FROM cg_outbox
                   WHERE event_id=? AND status='inflight' AND lease_owner=?
                     AND lease_until>?""",
                (event_id, worker_id, timestamp),
            ).fetchone()
            if row is None:
                raise OutboxLeaseLost("outbox event is not leased by this worker")
            attempts = int(row["attempts"])
            if attempts >= int(max_attempts):
                connection.execute(
                    """UPDATE cg_outbox SET status='review_required',
                       lease_owner=NULL, lease_until=NULL, last_error=?
                       WHERE event_id=?""",
                    (str(error)[:1000], event_id),
                )
                result = "review_required"
            else:
                connection.execute(
                    """UPDATE cg_outbox SET status='pending', next_attempt_at=?,
                       lease_owner=NULL, lease_until=NULL, last_error=?
                       WHERE event_id=?""",
                    (timestamp + max(0.0, float(delay_seconds)),
                     str(error)[:1000], event_id),
                )
                result = "retry_scheduled"
            connection.commit()
            return result
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def review_queue(self, *, limit: int = 100) -> list[dict]:
        """Return bounded, tenant-attributed events requiring operator review."""
        if not 1 <= int(limit) <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT event_id, operation_id, tenant_id, sequence, event_type,
                          payload_json, attempts, last_error, created_at
                   FROM cg_outbox WHERE status='review_required'
                   ORDER BY created_at, operation_id, sequence LIMIT ?""",
                (int(limit),),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result

    def queue_metrics(self, *, now: float | None = None) -> dict[str, int | float | bool | None]:
        """Expose queue depth, oldest pending age, retries and review alerts."""
        timestamp = time.time() if now is None else float(now)
        with self._connect() as connection:
            counts = connection.execute(
                "SELECT status, COUNT(*) AS count FROM cg_outbox GROUP BY status"
            ).fetchall()
            pending = connection.execute(
                """SELECT MIN(created_at) AS oldest_created_at
                   FROM cg_outbox WHERE status IN ('pending', 'inflight')"""
            ).fetchone()
            retries = connection.execute(
                """SELECT COALESCE(SUM(
                       CASE WHEN attempts > 1 THEN attempts - 1 ELSE 0 END
                   ), 0) AS retry_count FROM cg_outbox"""
            ).fetchone()
            total_attempts = connection.execute(
                "SELECT COALESCE(SUM(attempts), 0) FROM cg_outbox"
            ).fetchone()[0]
        values = {"pending": 0, "inflight": 0, "delivered": 0, "review_required": 0}
        values.update({row["status"]: int(row["count"]) for row in counts})
        oldest = pending["oldest_created_at"]
        pending_count = values["pending"] + values["inflight"]
        return {
            "queue_depth": pending_count,
            "pending": values["pending"],
            "inflight": values["inflight"],
            "delivered": values["delivered"],
            "review_required": values["review_required"],
            "oldest_pending_seconds": (
                max(0.0, timestamp - float(oldest)) if oldest is not None else 0.0
            ),
            "retry_count": int(retries["retry_count"] or 0),
            "total_attempts": int(total_attempts or 0),
            "review_alert": values["review_required"] > 0,
        }

    def outbox_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM cg_outbox GROUP BY status"
            ).fetchall()
        counts = {"pending": 0, "inflight": 0, "delivered": 0, "review_required": 0}
        counts.update({row["status"]: int(row["count"]) for row in rows})
        return counts
