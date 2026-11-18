# R4 supervised transactional outbox dispatcher

## Purpose and boundary

This worker drains committed CyberGuardian transactional-outbox events into the existing hash-chained audit ledger through `make_audit_ledger_sink`.

It is an audit-delivery worker only. It does not execute, resend, approve or retry remote agent/device commands. A local outbox commit proves that the gateway durably recorded a command-queue state transition; it does not prove that an agent received or executed the command.

Delivery is **at-least-once**. The worker always sends the stable outbox `event_id`. The ledger sink verifies the existing hash chain and accepts a duplicate only when the same ID has identical event content. A conflicting ID/content pair or corrupt ledger fails closed.

## Supervision and retry policy

- Each worker claims one eligible event using a time-limited SQLite lease.
- A worker may acknowledge or reschedule only while it still owns an unexpired lease.
- A process restart leaves an inflight lease recoverable after expiry.
- A second worker can reclaim expired leases; event order within an operation is preserved.
- Transient sink failures use exponential backoff, bounded by the configured maximum.
- After the configured maximum delivery attempts, the event transitions atomically to `review_required`; it is not retried indefinitely.
- Review-required events remain durable and block later events for the same operation, preserving operation event order until an operator investigates.
- If the sink accepted an event but the worker lost its lease before acknowledgement, the event may be delivered again with the same stable ID. The duplicate-aware ledger sink makes that replay safe.

The default Compose policy is eight attempts, starting at one second and capped at 300 seconds, with a 60-second lease. The eighth failed attempt moves the event to operator review.

## Persistent schema migration

The worker upgrades the existing `cg_outbox` status constraint to add `review_required`. The migration runs transactionally, copies all existing outbox rows and lease/retry metadata, recreates indexes, and rolls back on failure. Existing pending, inflight and delivered rows are preserved. The migration is safe to rerun.

## Docker deployment

The `outbox-worker` Compose service uses the same API image and the same persistent data bind mount as the API. It opens:

- SQLite database: `/app/data/cyberguardian.db`
- Hash-chained audit ledger: `/app/data/audit_ledger.jsonl`

It receives no administrator, dashboard, decision-service or agent API credentials. It refuses to create a new database if the configured API database is missing, preventing silent operation against a separate empty file; the restart policy allows it to start after API database initialization. It restarts automatically and has a Docker health check. A non-empty review queue causes `--health-once` to return a non-zero status so operators can see that intervention is required.

Start or update the stack from `deploy/docker` using the existing deployment procedure. Do not run the worker against a different database or ledger path from the API. Keep the SQLite database and WAL files on a local filesystem with reliable SQLite locking; do not share a SQLite database file over an unsupported network filesystem or between separate hosts.

## Operator commands

Run from the API container or the API source directory with the same mounted data volume:

```bash
python outbox_worker.py \
  --database /app/data/cyberguardian.db \
  --ledger /app/data/audit_ledger.jsonl \
  --health-once

python outbox_worker.py \
  --database /app/data/cyberguardian.db \
  --ledger /app/data/audit_ledger.jsonl \
  --review-queue --review-limit 100
```

The health output includes worker status, queue depth, pending/inflight/delivered counts, oldest pending age, retry count, total attempts, review-required count and a review alert. The review-queue command is read-only and returns tenant-attributed event metadata, payload, attempt count and the last safe error summary.

Do not manually change event status or delete outbox rows to clear an alert. Investigate the sink and ledger first, verify the ledger chain, compare the stable event ID and payload, and record an operator decision through the approved incident/change process. This PR intentionally does not provide an unaudited "force retry" or "discard" control.

## Monitoring and response

Alert when:
- the worker container is unhealthy or stops emitting health logs;
- queue depth or oldest pending age grows beyond the operator's service threshold;
- retry count increases persistently;
- any event enters `review_required`;
- the audit ledger is missing, unwritable or fails chain verification.

A review-required event is a human-intervention condition, not a reason to repeat a remote action. Preserve the database, WAL/SHM files, ledger and lock file during incident collection. Do not restore only the ledger or only the database from different points in time; reconcile the outbox and ledger by stable event ID after a coordinated backup restore.

## What this PR does not prove

- It does not prove remote agent receipt or device-side execution.
- It does not make remote actions exactly-once.
- It does not supply multi-host distributed database coordination.
- It does not complete physical outage, power-loss, multi-device or client tenant-isolation drills.
- It does not authorize a supervised client pilot or unattended 24-hour service.

Those remain separate client-readiness gates.
