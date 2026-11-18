# R4 transactional operation outbox

## Scope

This change adds a reusable SQLite transaction/outbox primitive. It is not a claim
that every existing CyberGuardian endpoint has been migrated to it. Existing
pilot middleware still has its separate audit-first intent/completion path and
must be adopted endpoint by endpoint after its side-effect boundaries are
classified.

## Transaction boundary

`SQLiteTransactionalOutbox.execute_operation` uses `BEGIN IMMEDIATE` and
commits all of the following together:

1. A tenant-scoped operation record and unique idempotency key.
2. An `operation_intent` outbox event.
3. Business-state changes made by the supplied handler on the exact same
   SQLite connection.
4. The final operation result and an `operation_completed` outbox event.

A handler exception rolls the entire transaction back. A retry with the same
(tenant, idempotency key, request fingerprint) returns the original operation
result without rerunning the handler. Reusing a key with a different request
fingerprint is rejected. Tenant ID is part of the uniqueness scope and all
operation lookups require tenant ID.

The database is configured for WAL mode, `synchronous=FULL`, foreign keys and
a bounded SQLite busy timeout. Keep the database on a local filesystem that
supports SQLite locking and WAL semantics; do not put this database on an
unsupported network filesystem or share a single SQLite file between hosts.

## Delivery and recovery

Outbox delivery is at-least-once, not exactly-once. Workers atomically claim
events with leases. Expired leases can be reclaimed after worker/process
failure. A successful receiver call followed by a worker crash before
acknowledgement can result in the same event being sent again with the same
stable `event_id`. The receiving system MUST persistently deduplicate by that
event ID. The dispatcher preserves event order within an operation: completion
cannot pass an unacknowledged intent. Failed deliveries return to pending with
a retry time and bounded error text.

The outbox cannot make a remote side effect atomic with a local SQLite
transaction. Handlers must restrict mutations to the supplied SQLite
connection. For a remote/device action, first persist an operation and
idempotency key, call a downstream API that itself supports durable
idempotency, then reconcile ambiguous outcomes by querying the downstream
operation ID. If the device/API has no idempotency or status-query facility,
do not automatically replay a disruptive action after an ambiguous timeout;
mark it for human reconciliation.

## Current integration limitation

This is the storage and dispatch foundation, not yet a wholesale migration of
the live pilot action middleware, agent command execution, or file-backed
state. Those call paths must be migrated separately and only where the
business mutation can share the SQLite transaction. The current JSONL audit
ledger remains an independent hash-chained evidence store. A production
adapter still needs a stable-ID, duplicate-aware ledger append path and a
recovery worker before outbox events can be declared reconciled into that
ledger.

Do not describe this PR alone as exactly-once execution, atomic remote
containment, production readiness, or 24-hour service readiness.

## Validation included

The tests cover atomic commit/rollback (including a hard subprocess exit),
same-key replay, request-fingerprint conflicts, tenant scoping, concurrent
duplicate submissions and worker claims, lease ownership/expiry, ordered
dispatch, delivery retry, reconciliation state, and the crash window after a
receiver accepts an event but before the sender acknowledges it. The crash-window test
demonstrates why the receiver's stable-ID deduplication contract is mandatory.

Physical network-loss, multi-device, power-loss, backup-restore, independent
audit-recovery, retention and incident-response drills remain deployment
acceptance work and are not represented by these automated tests.
