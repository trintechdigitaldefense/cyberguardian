# R4 Controlled Lab Execution and Evidence Pack

**Status:** PREPARED — no physical drill is claimed executed or passed by this document.  
**Target:** `r4-operational-drill-runbooks` only.  
**Release boundary:** CyberGuardian remains NO-GO for client deployment and unattended 24-hour operation.

## 1. Purpose and use

This pack turns the R4 operational-validation register into a controlled, repeatable lab session. It supplements, and does not replace, the detailed procedures in:

- `docs/R4_OPERATIONAL_VALIDATION_PHASE.md`
- `docs/R4_OPERATIONAL_DRILL_RUNBOOKS.md`
- `docs/R4_CLIENT_READINESS_DRILLS.md`
- `docs/R4_OUTBOX_FAILURE_DRILLS.md`

Use this pack to plan, authorize, execute, record and independently review each outstanding drill. Repository CI results must not be copied into physical-drill result fields.

## 2. Roles and authorization

Each drill requires named people before execution:

| Role | Responsibility |
|---|---|
| Lab owner | Confirms the environment is isolated, disposable and recoverable |
| Operator | Executes only the approved procedure and records timestamps |
| Independent witness | Observes execution and evidence collection; does not simply countersign their own work |
| Evidence reviewer | Checks raw evidence, pass criteria and redactions; may be the witness only if organizational policy permits |
| Service/release owner | Accepts remediation and makes the later release decision |

Record written authorization for each fault/outage drill. Approval must identify drill ID, scope, test asset(s), planned window, operator, witness, rollback/recovery method and stop conditions. A general project approval is not blanket authorization to interrupt a host, network, storage device or agent.

## 3. Mandatory pre-flight gate

Do not start a drill unless every applicable item is confirmed.

- [ ] Written authorization is approved for this exact drill and time window.
- [ ] Dedicated lab tenant and synthetic data are in use; no client production workload is connected.
- [ ] Lab owner confirms the target host, VM, agent, route or volume is disposable and uniquely identified.
- [ ] Operator and independent witness are present and their identities are recorded.
- [ ] Exact CyberGuardian commit SHA, agent build(s), configuration version, OS/kernel and filesystem are recorded.
- [ ] UTC clock synchronization is checked on controller, agent(s), host and evidence collector.
- [ ] Pre-test backup exists; restore has been tested where data could be damaged.
- [ ] Evidence destination is separate from the system being faulted, access-controlled and writable.
- [ ] Baseline database integrity, audit-chain verification, queue counts and relevant service health are recorded.
- [ ] Secrets are not placed in shell history, command-line arguments, logs, screenshots or Git.
- [ ] Rollback/recovery steps and stop conditions are understood by operator and witness.
- [ ] No production credentials, real customer records or destructive containment actions are involved.

**Abort before starting** if isolation, backup, identity, authorization, witness or evidence collection cannot be demonstrated.

## 4. Drill execution cards

### PROC-02 — outbox worker process crash and restart

**Objective:** Demonstrate supervised worker recovery, lease expiry/reclaim and idempotent audit delivery after abrupt worker termination.

**Safe scope:** Terminate only the dedicated outbox-worker process/container in an isolated lab Compose project. Do not stop the controller, API, host, agent, or any production service.

**Procedure:**
1. Record commit SHA, Compose project, container ID, worker health, database path and audit-ledger path.
2. Seed a uniquely identified synthetic audit event through the supported test path. Record its stable event ID and expected tenant.
3. Confirm the outbox row is pending/leased and capture its lease owner/expiry without exposing secrets.
4. At the approved fault point, abruptly terminate only the worker process/container. Record UTC termination time and exit result.
5. Confirm the controller/API and test database remain available; do not manually edit the outbox or ledger.
6. Restart the worker through the documented supervisor/Compose mechanism.
7. Where the first lease remains active, wait for its expiry; verify a new worker claims the same event using the stable event ID.
8. Verify the audit sink contains exactly one accepted record for that event ID and the outbox reaches its acknowledged/delivered state.
9. Verify event ordering and tenant attribution. Confirm no remote/device command was replayed.
10. Export logs and state snapshots, then stop the lab stack cleanly.

**PASS only if:** worker restart is observed; expired lease is safely reclaimed; stale owner cannot acknowledge; stable event ID is preserved; exactly one ledger record exists; outbox acknowledgement is durable; no remote command replay occurs.

**FAIL/STOP:** duplicate ledger records, changed event content under the same ID, cross-tenant attribution, lost event, stale-owner acknowledgement, unbounded retry, unexpected remote action or ledger-integrity error.

### HOST-01 — abrupt power-loss recovery

**Objective:** Establish recovery behaviour after an actual abrupt power interruption on a disposable lab VM/host with synthetic writes active.

**Safe scope:** A dedicated disposable VM or lab host only. Never use a client system, shared host, workstation containing unique data, or the only copy of evidence.

**Procedure:**
1. Obtain explicit written approval for abrupt power interruption. Confirm hypervisor/host owner, VM identity, snapshot/backup ID and independent evidence capture.
2. Verify and record pre-test SQLite integrity, audit-chain status, outbox counts, ledger head/hash, service health and pending event IDs.
3. Start controlled synthetic writes and record the exact test event IDs and UTC time window.
4. At the approved point, use the lab hypervisor or physical lab control to remove power abruptly. Do not substitute graceful shutdown and label it a power-loss test.
5. Record the hypervisor/physical power event independently. Do not alter the disk image or manually repair SQLite files.
6. Restore power and boot the disposable host. Capture boot, filesystem and service-recovery logs.
7. Run the documented SQLite integrity check and audit-chain verification before accepting new test traffic.
8. Reconcile pre-fault accepted events against outbox and ledger state. Identify committed, rolled-back and ambiguous operations separately.
9. Confirm no ambiguous remote/device operation is replayed automatically; require human reconciliation.
10. Preserve the VM snapshot/disk evidence and all logs for independent review.

**PASS only if:** recovery is repeatable; SQLite integrity passes; audit chain verifies; committed outbox events reconcile to ledger records; no acknowledged event is silently lost or duplicated; ambiguous remote operations remain human-gated.

**FAIL/STOP:** filesystem or database corruption without safe recovery, unverifiable audit chain, missing accepted events, duplicate effects, unexpected command replay or loss of the pre-test evidence copy.

### NET-01/02 — physical test-agent network interruption and reconnect

**Objective:** Prove one designated physical test agent safely queues synthetic telemetry while disconnected and drains it after connectivity returns.

**Safe scope:** Isolate only the designated lab agent's network path. Do not modify shared firewall policy, controller routing or unrelated devices.

**Procedure:**
1. Record agent asset ID, tenant, agent build, controller build, queue location, route and baseline heartbeat/queue count/hash.
2. Confirm at least three unique synthetic event IDs can be generated and observed at the controller.
3. Block only the test agent's route at the lab network boundary for the approved duration.
4. Generate at least three additional uniquely identified benign events. Record local queue count and hashes; confirm no controller acknowledgement is received.
5. Restart the test agent while disconnected, if the approved test plan includes restart. Confirm queued records remain parseable and present.
6. Restore only the test agent's network route. Do not delete or edit queue files.
7. Observe bounded retry and queue drain. Match every accepted event ID to the controller acknowledgement.
8. Verify retries do not create duplicate controller business records; retain before/during/after evidence.
9. Confirm other lab systems were not interrupted.

**PASS only if:** no accepted event disappears; queue survives the optional agent restart; all expected events are acknowledged; queue drains only after acknowledgement; retries are bounded and duplicate-safe.

**FAIL/STOP:** event loss, queue corruption, cross-tenant delivery, unexpected disruption to another system or a remote action.

### STORE-01 — storage failure and recovery

**Objective:** Establish fail-closed behaviour and recoverability when a disposable CyberGuardian data volume becomes unavailable or read-only.

**Safe scope:** A dedicated disposable data volume containing only synthetic lab state. Never fault the host root filesystem, shared storage, production disk or sole evidence copy.

**Procedure:**
1. Record volume/device identity, mount options, filesystem, database/ledger paths, baseline hashes, SQLite integrity, audit-chain result and outbox counts.
2. Verify a separate pre-test backup and a tested restore route. Confirm evidence collector is not on the target volume.
3. Obtain approval for the exact storage fault method. Use a lab-only mechanism to make the test volume unavailable or read-only.
4. Observe service behaviour. Confirm writes fail closed and errors are visible; do not bypass errors or silently switch to an unverified path.
5. Restore the volume using the approved lab procedure. Preserve filesystem/kernel/service logs.
6. Run filesystem checks only as appropriate to the disposable test volume and documented recovery process.
7. Run SQLite integrity and audit-chain verification before resuming test writes.
8. Reconcile outbox rows, ledger events and pre-test synthetic event IDs. Restore from the verified backup only if required and document every recovery action.
9. Confirm the service resumes without duplicate delivery or silent evidence loss.

**PASS only if:** storage errors are visible; unsafe writes fail closed; recovery preserves or restores verified data; SQLite and audit checks pass; reconciliation accounts for every expected event.

**FAIL/STOP:** silent write success to an unintended path, corruption not safely recoverable, missing evidence, chain mismatch or cross-tenant state.

### DEV-01 — multi-device operation

**Objective:** Demonstrate two independently enrolled physical lab agents can operate concurrently and retain distinct identity and lifecycle.

**Safe scope:** At least two disposable physical test devices, synthetic events and a lab tenant. Distinct per-agent credentials are mandatory.

**Procedure:**
1. Record both device models/OS versions, agent builds, unique asset IDs and non-secret credential fingerprints.
2. Enrol Agent A and Agent B independently. Do not share bootstrap or long-lived secrets.
3. Confirm both assets appear exactly once and have independent heartbeats.
4. Generate distinguishable synthetic events concurrently from each agent; correlate source asset, event ID and controller record.
5. Disconnect Agent A only. Observe stale/offline transition while Agent B remains online and continues reporting.
6. Reconnect Agent A. Confirm heartbeat recovery updates the same asset without duplicate inventory.
7. Revoke Agent A's old credential and confirm it is rejected; rotate/re-enrol through the supported process. Confirm Agent B remains unaffected.
8. Export redacted inventory, heartbeat, event-correlation and audit evidence.

**PASS only if:** device identity remains distinct; concurrent events map to the correct source; offline/reconnect lifecycle is correct; revoked credentials fail; no duplicate asset or cross-device/tenant leakage occurs.

### TEN-01 — tenant isolation

**Objective:** Demonstrate authorization boundaries using two separately authenticated lab tenants and operators.

**Safe scope:** Two dedicated synthetic tenants and separately issued credentials. No real customer data.

**Procedure:**
1. Record tenant A/B identifiers and operator/agent credential fingerprints. Do not record secret values.
2. Create unique synthetic assets, events, reports and audit entries in each tenant.
3. As Tenant A, verify permitted access to A resources and attempt read/list/mutate/reconcile access to B resources through supported APIs.
4. Repeat as Tenant B against A resources.
5. Test missing tenant context, mismatched tenant/resource identifiers and revoked credentials.
6. Verify denied attempts are recorded appropriately without exposing the other tenant's data in responses, logs or reports.
7. Review tenant-scoped database assertions and audit evidence with the independent witness.

**PASS only if:** all allowed requests are scoped correctly; every cross-tenant or context-free attempt is denied; no data, metadata, counts, report rows or evidence leak across tenants; denials are auditable.

**FAIL/STOP:** any cross-tenant visibility or mutation, ambiguous authorization result, accepted revoked credential or missing tenant context accepted as trusted.

### AUD-01 — independent audit backup, restore and append

**Objective:** Prove an audit backup can be independently retrieved, verified and restored to a clean instance without trusting the source host.

**Safe scope:** Synthetic audit records, separate recovery host and independently administered backup destination. Keep HMAC/signing keys outside the backup and source host.

**Procedure:**
1. Verify source audit chain. Record source commit, ledger head/hash, record count and UTC time.
2. Export a signed checkpoint and manifest using the documented backup procedure.
3. Transfer snapshot and manifest to independently administered storage. Record destination control owner and object digest.
4. On the recovery host, retrieve the snapshot independently. Retrieve the verification key through the approved secret-management process; never put it in Git, shell history or command arguments.
5. Verify manifest authentication, snapshot digest, record count and hash chain before restore.
6. Restore into a new, empty audit path on a clean instance. Do not overwrite a live ledger.
7. Compare restored record count and head/hash with the verified source checkpoint.
8. Append one clearly labelled synthetic recovery event using the supported gateway path.
9. Re-verify the chain and confirm original records are unchanged and the new record extends the chain.
10. Record independent custody of source, backup destination, key and recovery instance.

**PASS only if:** backup is retrievable without source-host access; authentication/digest/count/chain verify; clean restore succeeds; original records remain unchanged; new append verifies; independent custody is demonstrated.

**FAIL/STOP:** missing key/manifest, digest mismatch, chain error, overwrite attempt, source-host dependency or inability to independently retrieve the backup.

## 5. Evidence bundle and per-drill record

Create one restricted evidence bundle per drill. Store raw sensitive logs outside Git in the approved evidence repository. Commit only a redacted summary and evidence reference approved for repository use.

Copy and complete this record for each drill:

```text
Drill ID:
Result: NOT RUN | BLOCKED | INCONCLUSIVE | FAIL | PASS
Authorization reference:
Environment / lab tenant:
Target host / VM / agent / volume:
CyberGuardian commit SHA:
Agent build(s):
OS / kernel / filesystem:
Operator:
Independent witness:
Evidence reviewer:
UTC start:
UTC end:
Pre-flight checklist complete: YES / NO
Pre-test backup reference and verification:
Baseline measurements:
Fault injected and exact UTC timestamp:
Expected outcome:
Observed outcome:
Event IDs / asset IDs (synthetic only):
SQLite integrity result:
Audit-chain result:
Outbox / ledger reconciliation:
Unexpected effects / deviations:
Evidence bundle reference and digest:
Remediation issue / PR:
Operator attestation:
Witness attestation:
Reviewer decision:
```

### Evidence handling

- Use UTC timestamps and preserve original logs.
- Record exact commit and tool versions; do not rely on branch names alone.
- Redact credentials, tokens, private keys, personal data and client identifiers.
- Keep raw evidence in restricted storage, not GitHub.
- Hash evidence bundles and retain the manifest separately where policy requires.
- Preserve failed and inconclusive evidence; do not overwrite it with a later passing run.
- A result is PASS only after every criterion is met and an authorised second person reviews the evidence.

## 6. Result register

The following states are the baseline at preparation time. Update only after execution and review.

| ID | Drill | Initial state | Evidence required before PASS |
|---|---|---|---|
| COMPOSE-01 | Sustained Compose worker health | PASS — CI only | Exact-head Actions evidence; this does not count as a physical drill |
| PROC-02 | Outbox worker process crash/restart | NOT RUN | Worker restart, lease recovery, stable ID, one ledger record, no remote replay |
| HOST-01 | Abrupt power-loss recovery | NOT RUN | Independent power event, SQLite integrity, ledger verification, reconciliation |
| NET-01/02 | Physical agent network interruption/reconnect | NOT RUN | Physical route isolation, queue survival, acknowledged drain, duplicate check |
| STORE-01 | Disposable storage failure/recovery | NOT RUN | Fail-closed logs, volume recovery, SQLite/ledger verification, reconciliation |
| DEV-01 | Two physical agents | NOT RUN | Independent enrollment, concurrent events, lifecycle and credential evidence |
| TEN-01 | Two-tenant isolation | NOT RUN | Allowed/denied request evidence, DB assertions, second-person review |
| AUD-01 | Independent audit backup/restore/append | NOT RUN | Off-host retrieval, manifest/digest/chain verification, clean restore and append |

Do not mark COMPOSE-01 as evidence that physical power, network, storage or multi-device conditions passed.

## 7. Stop conditions and incident handling

Stop the current drill immediately and preserve the environment/evidence if any of the following occurs:

- data or queued events disappear unexpectedly;
- SQLite integrity or audit-chain verification fails;
- a tenant sees or modifies another tenant's information;
- revoked credentials are accepted;
- an unexpected remote/device action occurs;
- an operation is replayed automatically when its outcome is ambiguous;
- the test affects a non-target host, route, device, tenant or volume;
- evidence capture fails or the only backup becomes unavailable.

Do not continue to the next drill until the incident is documented, its scope is understood and the release owner authorizes resumption.

## 8. Release gate

This pack does not confer client-readiness. The R4 release owner must review every drill's evidence, confirm remediation of failures, validate the exact final R4 commit and document a separate release decision. Even a complete lab pass is not by itself proof of 24-hour unattended service, production resilience, contractual suitability or client deployment approval.

**Current decision remains: NO-GO for client deployment and unattended 24-hour operation.**
