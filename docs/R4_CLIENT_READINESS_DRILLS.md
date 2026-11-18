# R4 client-readiness and operational drill record

## Status

**Not executed — deployment access required.** This document is the controlled drill
procedure and evidence record template. Repository CI and simulated tests are
not substitutes for tests on the actual pilot host, network and enrolled
devices. Do not fill a result as PASS without retaining the evidence listed
below.

## Preconditions and safety

- Use a dedicated, non-production pilot tenant and approved test devices.
- Obtain written approval for each outage, restart and containment exercise.
- Record the exact CyberGuardian build SHA, agent versions, host OS/kernel,
  database location, network topology, operator, witness and UTC start/end.
- Use benign test events and non-disruptive commands. Do not test destructive
  containment against a client production network.
- Confirm backups and a tested restore point before power-loss or storage
  failure tests.
- Stop immediately if tenant boundaries, evidence integrity or device safety
  cannot be demonstrated.

## Drill matrix

| ID | Drill | Procedure | Pass criteria | Evidence to retain |
|---|---|---|---|---|
| NET-01 | Network outage | Disconnect one test agent from the controller for 15 minutes while generating uniquely identified benign telemetry. | Agent remains healthy; queue persists locally; no silent drops; queue capacity/overflow behaviour is explicit. | Agent logs, queue counts, event IDs, network timestamps. |
| NET-02 | Network recovery | Restore connectivity and observe queue replay. | Every accepted event is acknowledged; duplicate event IDs do not duplicate controller effects; backlog drains without manual deletion. | Before/after queue export, controller records, replay summary. |
| PROC-01 | Agent restart | Stop/restart the agent with queued records and again while a delivery is in flight. | Pending data survives restart; in-flight events retry with stable IDs; no queue corruption. | Service logs, queue file metadata/hash, controller event IDs. |
| HOST-01 | Abrupt host restart | On a disposable host, perform an approved abrupt restart while the database and queue are active. | SQLite recovery completes; no partial business/outbox transaction; integrity checks pass; ambiguous remote actions are reconciled, not replayed blindly. | System journal, SQLite integrity check, operation/outbox counts, audit verification. |
| DEV-01 | Multi-device | Enrol at least two physical agents in one test tenant; submit distinct events concurrently. | No cross-device event loss or ID collision; each device remains independently identifiable. | Device inventory, agent logs, event correlation report. |
| TEN-01 | Tenant isolation | Use two test tenants and two separately authenticated operators/agents; attempt permitted and denied reads/actions. | No tenant can read, mutate, or reconcile another tenant's operations, reports, events or evidence. | Authenticated request/response captures with secrets redacted, DB query assertions, audit records. |
| OUT-01 | Outbox recovery | Stop dispatcher after sink acceptance but before acknowledgement; restart after lease expiry. | Same event ID is retried; sink deduplicates persistently; event ordering is maintained; no duplicate downstream effect. | Outbox rows, worker logs, sink deduplication record. |
| AUD-01 | Audit recovery | Export a verified audit checkpoint to independent storage; restore to a separate host and verify signature, digest and chain. | Restored record count/head match; tampering is detected; original evidence is unchanged. | Signed manifest, snapshot SHA-256, restore logs, verification output. |
| RET-01 | Retention | Obtain client approval for data classes and retention periods; test expiry and legal-hold behaviour in a disposable dataset. | Only approved data is retained; expiry is auditable; legal holds prevent premature deletion; evidence is not silently altered. | Approved schedule, test records, deletion/hold audit. |
| IR-01 | Incident response | Simulate a test agent credential compromise: revoke, rotate, isolate, investigate, restore and close. | Revoked credentials cannot reconnect; evidence is preserved; response owner/timings and client notification path are demonstrated. | Timeline, revocation logs, key-rotation record, incident report. |

## Acceptance rule

A drill is PASS only when every pass criterion is met and evidence is reviewed by
a second authorised person. FAIL, BLOCKED, NOT RUN and INCONCLUSIVE are distinct
states. Any unresolved tenant leak, evidence-integrity failure, unbounded
queue-loss condition, or repeatable disruptive-action replay is an automatic
stop and blocks client pilot approval.

## Execution record

For each drill, append: ID, date/time, build SHA, environment, operator,
witness, expected result, actual result, PASS/FAIL/BLOCKED/NOT RUN,
evidence location and remediation issue/PR. Keep raw evidence in the approved
client evidence store; do not commit client identifiers, secrets or raw
sensitive telemetry to this repository.
