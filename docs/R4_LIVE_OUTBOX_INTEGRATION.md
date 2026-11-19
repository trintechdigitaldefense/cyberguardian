# R4 live transactional outbox integration

## Scope

This change connects the existing transactional outbox to the gateway's SQLite-backed agent-command polling state transition at `GET /v1/agent/commands`.

When an enrolled agent polls for commands, the gateway:
1. Opens the existing CyberGuardian application database.
2. Selects queued commands for the authenticated asset.
3. Marks eligible commands as delivered (or expired) using compare-and-set updates.
4. Writes the operation record plus durable `operation_intent` and `operation_completed` events through the **same SQLite connection and transaction**. The completion payload contains an `audit_events` array with one structured record per delivered or expired command.
5. Commits the command-state changes and outbox events together.
6. Returns the selected commands to the agent.

The outbox tables live in the same `DB_PATH` database as `agent_commands`. The new `execute_operation_on_connection` API refuses a connection that already has an open transaction, uses `BEGIN IMMEDIATE`, sets a full-synchronous commit policy, and rolls back business writes and outbox rows together on exceptions.

## What this guarantees

- A crash before commit leaves neither the command-state transition nor its outbox intent/completion records committed.
- A crash after commit leaves the command-state transition and durable outbox records available for recovery and later audit delivery.
- Tenant identity is derived from the registered asset row in the application database; an unregistered asset or missing tenant attribution fails closed. The asset-to-tenant mapping is rechecked inside the same write transaction before any command status transition. The resolved tenant is copied into both operation and outbox rows.
- Each command audit record retains the prior per-command forensic fields: event type, command ID, pending-action ID, action, target, asset ID, actor and detail; delivered records also retain decision and detection IDs, while expired records retain the failed result status.
- The per-command records are durably nested in the `operation_completed` event's `result.audit_events` array and are committed atomically with the command status transitions.
- The existing asset-bound agent credential checks, tenant checks, single-use compare-and-set command transition, command expiry handling and command-signing middleware remain in place.
- The outbox event sink can later deliver the committed events with stable event IDs.

## Important boundary: command delivery is not remote execution

This transaction covers the gateway's local command-queue state transition and its audit intent/completion records. It does **not** make a remote device action atomic with SQLite, and it does not prove that the agent received or executed the HTTP response.

If the gateway commits the command as delivered and then loses the response before the agent receives it, the current command protocol may require operator reconciliation. The outbox must not automatically re-run a remote containment action to compensate. A future delivery-acknowledgement/lease protocol and downstream command idempotency are required before claiming crash-safe remote command execution.

The generic `operation_completed` event means the local queue transition completed; the event result is explicitly tagged `agent_commands_claimed`. It does not mean a host was isolated, a process was stopped, or any other device-side action succeeded.

## Explicit exclusions

The following remain outside this integration:
- `GET /health`: read-only health check; no mutation queue entry.
- `POST /v1/client-mode`: writes file-backed gate configuration, not part of the SQLite transaction.
- `POST /v1/issues/remember`: uses the separately locked JSONL issue-memory store.
- `POST /v1/issues/auto-remediate`: can initiate remote/device-side work; no SQLite transaction can atomically commit that effect.
- Other file-backed, external-service, and remote-agent effects until each has a safe idempotency and reconciliation design.

No claim is made that all pilot endpoints are transactionally protected.

## Validation required

The automated suite must prove:
- business-state writes and outbox rows commit on the same connection;
- an exception before commit rolls back both;
- nested/open transactions are rejected;
- tenant IDs are preserved in operation and event rows;
- existing outbox replay, lease, ordering and audit-sink tests remain green;
- gateway source assembly and the complete regression/security workflows pass on the exact PR head.

The physical network, host-power, multi-device and tenant-isolation drills remain separate release gates. This integration alone does not change the client-pilot or 24-hour release decision.
