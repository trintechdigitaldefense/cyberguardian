# R4 Operational Validation Phase

**Target branch:** `r4-operational-drill-runbooks`  
**Status:** IN PROGRESS — no physical operational drill is recorded as passed.  
**Release boundary:** CyberGuardian remains NO-GO for client deployment and unattended 24-hour operation.

## Objective

Turn the R4 reliability work into independently reviewable operational evidence. A green unit-test or Compose job is evidence only for the paths exercised by that job. It does not certify the host, filesystem, physical network, enrolled devices, off-host backup boundary, or an unattended service.

This phase is limited to R4. Keep `main` and R5 outside this work. Do not connect these exercises to a client production network.

## Gate 1 — sustained Compose outbox-worker health

The Compose acceptance job must prove more than that the worker container started:

1. Start the production-mode Compose stack with a fresh, isolated data directory and unique ephemeral credentials.
2. Locate the single `outbox-worker` container for that Compose project.
3. Wait for Docker to report `healthy`; fail on an exited or `unhealthy` container or when the start deadline expires.
4. Keep the worker running and healthy for at least 70 seconds.
5. Require at least two successful Docker health-check executions completed inside that observation window. Any failed check during the window fails the gate, even if Docker has not yet changed the container state to `unhealthy`.
6. Record the project, short container ID, observation duration, health-check result count and timestamps in CI output.

The gate is implemented by `scripts/verify_compose_outbox_health.py` and is invoked after the existing Compose supervised-workflow exercise. It is a supervised CI health-stability check, not proof of 24-hour availability or physical host recovery.

For a running isolated Compose project, it can also be invoked manually from the repository root:

```bash
python3 scripts/verify_compose_outbox_health.py \
  --project cg-compose-ci \
  --compose-file deploy/docker/docker-compose.yml
```

Use the same project name and Compose file used to start the stack. Do not point the verifier at a client or production stack.

## Gate 2 — operator-run physical and recovery drills

The procedures in `docs/R4_CLIENT_READINESS_DRILLS.md` and `docs/R4_OPERATIONAL_DRILL_RUNBOOKS.md` remain the controlling runbooks. The following sequence makes the outstanding evidence explicit.

| ID | Validation | Required evidence for PASS | Current state |
|---|---|---|---|
| COMPOSE-01 | Sustained worker health in isolated Compose | Exact commit, CI run/job, worker reaches `healthy`, at least two successful health-check executions across the 70-second observation, no failed checks | PENDING CI |
| PROC-02 | Abrupt outbox-worker process termination and restart | Worker/container timeline, lease recovery, stable event ID, one ledger record, delivered outbox state, no remote-command replay | NOT RUN |
| HOST-01 | Abrupt host/power-loss recovery on a disposable host or VM | Hypervisor/power event timeline, SQLite `integrity_check`, outbox/ledger reconciliation, audit-chain verification, restart logs | NOT RUN |
| NET-01/02 | Physical test-agent network interruption and reconnect | Before/during/after queue counts and hashes, synthetic event IDs, timestamps, controller acknowledgements, duplicate check | NOT RUN |
| STORE-01 | Storage unavailability/read-only failure and recovery on a disposable data volume | Volume/device events, preserved pre-test backup, fail-closed behaviour, SQLite integrity result, audit-chain verification, reconciliation report | NOT RUN |
| DEV-01 | At least two independently enrolled physical agents | Device inventory, distinct credential identifiers/fingerprints, heartbeat/offline/reconnect timeline, correlated event delivery | NOT RUN |
| TEN-01 | Two-tenant authorization and isolation | Redacted authenticated requests, allowed/denied results, tenant-scoped DB assertions, audit events reviewed by a second operator | NOT RUN |
| AUD-01 | Independent audit backup, restore and post-restore append | Signed manifest, off-host snapshot digest, key-custody record, clean-instance restore output, record count/head comparison and successful chain verification after a new synthetic append | NOT RUN |

### Safety controls

- Obtain written approval for each outage, restart, power-loss or storage-failure exercise. Use a dedicated lab tenant, synthetic records and disposable devices/VMs.
- Confirm a recoverable backup and tested restore path before any power or storage fault injection.
- For HOST-01, use a disposable VM or lab host with no client workload. Exercise abrupt power removal while test writes are active; a graceful shutdown is not an equivalent power-loss test.
- For PROC-02, terminate only the outbox worker in the isolated test stack. Confirm restart supervision, wait through lease expiry where required, and verify the stable event ID at the ledger. Do not disrupt the API or a client service.
- For STORE-01, fault only a disposable data volume. Never remount the host root filesystem read-only, detach a production disk, or risk the only copy of evidence.
- For NET-01/02, isolate only the designated test agent's route. Do not change shared controller firewall rules or disconnect unrelated devices.
- Keep Client Mode enabled. Use benign telemetry and non-disruptive actions. Never replay a remote/device command to resolve an ambiguous result.
- Stop immediately on data loss, evidence-integrity failure, cross-tenant visibility, acceptance of revoked credentials, or unexpected disruptive action.

## Evidence and acceptance

For every drill, retain the exact commit SHA, environment/host and OS or kernel details, configuration summary, operator and independent witness, UTC start/end, expected and actual results, redacted logs, relevant IDs/hashes, status and remediation reference. Store raw sensitive evidence in the approved restricted evidence location, not in Git.

Use only these result states: **PASS**, **FAIL**, **BLOCKED**, **NOT RUN**, or **INCONCLUSIVE**. A drill is PASS only when every criterion is met and a second authorised reviewer has inspected the retained evidence. A failed or inconclusive result stays visible and blocks the relevant release gate; do not overwrite it with a later successful run without retaining both records and explaining the remediation.

The owner of the environment must execute and attest the physical drills. Repository automation cannot manufacture evidence of physical power loss, network isolation, storage failure, a second device, an independently administered backup destination, or a real tenant boundary.

## Release decision

No pilot-client or unattended-service approval follows automatically from this phase or from CI. Reconsider the R4 release decision only after all mandatory operational gates have retained evidence, unresolved failures are remediated, the exact final R4 head has passed validation, and the authorised release review is signed off.
