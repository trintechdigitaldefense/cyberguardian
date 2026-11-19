# R4 outbox crash, retry and reconciliation failure drills

## Purpose

This test phase exercises failure boundaries that ordinary happy-path regression tests cannot establish. It is automated fault-injection evidence only; it does not replace physical host/network/power drills.

## Automated scenarios

- **Crash before transaction commit:** terminate a child process after a business-state write but before commit; verify SQLite recovery leaves no business mutation, operation row or outbox event.
- **Crash after sink fsync, before outbox acknowledgement:** terminate the worker after the hash-chained ledger accepts an event; reclaim the expired lease and replay the same stable event ID; verify the ledger has one record and the outbox is acknowledged.
- **Lease expiry and stale owner:** allow a lease to expire, reclaim it with another worker, and prove the old worker cannot acknowledge the event.
- **Retry and backoff:** retain bounded exponential retry and maximum-attempt escalation coverage from the worker suite.
- **Duplicate delivery:** identical stable ID and content is accepted as a replay; same ID with different content fails closed.
- **Ledger corruption:** mutate an existing ledger record and prove new outbox delivery is blocked without appending.
- **Reconciliation:** persist tenant-scoped reconciliation_required, preserve event ordering, reject cross-tenant access, and ensure repeated reconciliation requests do not create duplicate reconciliation events.

## Safety interpretation

The dispatcher transports audit events only. It never repeats a remote agent/device command. A lost agent response after a local command-queue commit is an ambiguous outcome requiring human reconciliation; it is not permission for automatic command replay.

## Evidence to retain

For each run retain the exact commit SHA, workflow run and job IDs, test output, test environment, injected failure point, database/ledger hashes, and resulting outbox/ledger state. Record failed or inconclusive drills as release blockers.

## Release boundary

Passing these tests establishes only the tested software failure behaviour under the test harness. It does not prove recovery after real power loss, network partition, storage failure, host restart, multi-device deployment or tenant-isolation drills in a client environment. CyberGuardian remains NO-GO for client deployment and unattended 24-hour operation until those operational drills and release gates are completed and approved.
