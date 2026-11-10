# R4 Operational Drill Runbooks

**Status:** Procedures prepared; no field drill is claimed complete by this document.  
**Scope:** CyberGuardian R4 only. Use disposable lab devices and synthetic client data.

These drills produce the evidence that CI cannot: a real network interruption, an independently administered backup destination, physical agent reconnect, and operator-approved data-retention policy. Keep Client Mode enabled. Do not execute disruptive containment during these drills.

## 1. Offline queue: network partition and reconnect

### Preconditions
- One controller and one enrolled Linux/Termux agent in an isolated lab.
- Unique per-agent API, identity and command credentials; no shared bootstrap credential.
- Controller reachable before the drill; clocks synchronized.
- A known event-generation method and access to the agent's private queue/status directory.
- Record the agent asset ID, software commit, OS/kernel/filesystem, queue path, start time and controller URL (redact secrets).

### Procedure
1. Confirm the agent heartbeat is visible and record its `last_seen`.
2. Record the queue count and queue file SHA-256 before the drill.
3. Block only the test agent's route to the controller at the lab network boundary. Do not change controller firewall policy or disconnect other systems.
4. Generate at least three uniquely identified synthetic events while disconnected. Confirm the agent reports delivery failure and the queue count increases.
5. Restart the agent while the partition remains in place. Confirm all pending records remain present and parseable; record the queue count and SHA-256 again.
6. Restore the network path. Do not manually delete or edit queue files.
7. Wait for bounded retry/flush. Confirm the queued events are accepted by the controller and the pending queue drains only after acknowledgements.
8. Replay or inspect controller event IDs to confirm retries did not create duplicate business records for the idempotent detection endpoint.
9. Repeat once with a deliberately unacknowledged event or controlled controller outage, then restore service and verify that the event remains queued until acknowledged.

### Pass criteria
- No event disappears during partition or agent restart.
- Queue files remain private and valid; no partial/corrupt records are silently discarded.
- Reconnect delivers all pending records; only acknowledged records are removed.
- Retries are bounded and observable; matching detection replay does not duplicate the protected controller transaction.
- Capture timestamps, queue counts/hashes, agent/controller logs, event IDs and final controller query results.

### Fail / stop
Stop if queue data is lost, permissions weaken, the controller receives cross-tenant events, or the agent attempts disruptive actions. Preserve the queue and logs for investigation.

## 2. Audit durability: independently stored backup and clean-instance restore

### Preconditions
- A disposable source controller containing synthetic audit records.
- A second host or independently administered storage account/volume not mounted writable by the source controller.
- A separately provisioned recovery environment with a clean data directory.
- The audit checkpoint HMAC key transferred through an approved secret manager or secure offline process. Never commit, paste, log, or pass the key as a command-line argument.

### Procedure
1. On the source, verify the current ledger before export. Record source commit, ledger path, record count and export time.
2. Export a signed checkpoint to a staging directory, then transfer the snapshot and manifest to the independently administered destination. Keep the key outside the snapshot destination and source repository.
3. On the independent destination, verify the snapshot and manifest using the separately retrieved key. Record the digest, record count, and verification result.
4. Provision a clean CyberGuardian instance from the intended release commit. Confirm its audit destination does not contain the source ledger.
5. Transfer the verified snapshot to the recovery instance through the approved recovery channel and restore to a new, empty audit path. Do not overwrite a live ledger.
6. Verify the restored chain and compare record count and digest to the verified snapshot.
7. Start the recovery gateway against the restored ledger in an isolated environment. Confirm it can read existing history and append one clearly labelled synthetic recovery event.
8. Re-run chain verification and confirm the original records remain unchanged and the new event extends the chain.
9. Record who controlled the source, backup destination, key and recovery instance. These should not all be the same trust boundary.

### Pass criteria
- Backup exists outside the source host and is readable without relying on source-host storage.
- Manifest HMAC, snapshot digest, record count and hash chain all verify.
- Clean-instance restore succeeds without overwriting an existing file.
- Gateway reads the restored ledger and appends a new event while preserving chain integrity.
- Evidence includes source/destination identifiers, timestamps, release commit, tool output (with secrets redacted), digests, record counts and operator signoff.

### Fail / stop
A missing manifest, wrong key, digest mismatch, chain error, overwrite prompt, or inability to retrieve the backup independently is a failure. Preserve artifacts; do not bypass verification.

## 3. Issue memory: retention schedule approval

Retention is a client governance decision, not a value to infer from a code default. Before enabling production archival rotation, obtain written approval from the client data owner and TrinTech Digital Defense's designated service owner.

Complete and sign the policy record in `docs/R4_RETENTION_APPROVAL.md`. It must specify:
- Active issue-memory retention period.
- Archived issue-memory retention period.
- Backup retention and deletion schedule, including replicas.
- Legal hold / investigation exception and who can authorize it.
- Deletion method, verification evidence and responsible operator.
- Data owner, approving authority, effective date, review date and applicable client contract/policy.
- Whether client-specific schedules override the default.

Until approval is recorded, do not claim the retention gate passed or enable irreversible purge/rotation based on an assumed period. Keep current bounded-store safeguards and preserve evidence.

## 4. Fleet: multi-agent lifecycle and physical reconnect

### Preconditions
- At least two enrolled disposable agents with distinct per-agent credentials.
- Prefer two tenants to test isolation; otherwise use two assets in one tenant and explicitly note that cross-tenant isolation was not exercised.
- One controller and access to fleet, enrollment, heartbeat and audit views.
- A repeatable way to power down or disconnect one test agent.

### Procedure
1. Enroll Agent A and Agent B with unique asset IDs and independent API, identity and command secrets. Record only secret fingerprints/IDs, never secret values.
2. Confirm both appear once in inventory, under the correct tenant, and both heartbeat as online.
3. Disconnect Agent A physically (power off or remove its network path). Keep Agent B connected.
4. Wait beyond the configured stale threshold. Confirm A becomes offline/stale and B remains online.
5. Restore Agent A's physical/network connection. Confirm its signed heartbeat refreshes `last_seen`, A returns online, and no duplicate inventory row is created.
6. Revoke Agent A's credential and confirm its heartbeat/command poll is rejected. Confirm Agent B remains unaffected.
7. Re-enroll the same asset with fresh credentials using the supported enrollment process. Confirm only the new credential works.
8. Query each tenant's fleet and verify it cannot see the other tenant's agents, lifecycle details or credential metadata.
9. Preserve timestamps, asset IDs, redacted API responses, audit events and screenshots/log extracts.

### Pass criteria
- Unique per-agent identity is maintained; no shared secret is used.
- Online → offline → online transition follows heartbeat timestamps and configured threshold.
- Reconnect updates the existing asset rather than creating duplicates.
- Revocation immediately blocks old credentials; re-enrollment uses fresh credentials.
- Tenant boundaries hold throughout; the other agent remains healthy during the drill.

### Fail / stop
Stop on cross-tenant visibility, accepted revoked credentials, duplicate asset creation, or unexplained loss of Agent B. Do not test against client production agents.

## 5. Reporting: provenance and repeatable date windows

### Preconditions
- Synthetic, tenant-separated source records with known IDs, event timestamps and known expected inclusion/exclusion.
- A fixed report timezone and explicit inclusive/exclusive boundary convention.
- Read-only access to source records and report outputs.

### Procedure
1. Seed or select synthetic records before, exactly at, within, exactly at the end of, and after the target report window. Include records for a second tenant.
2. Record source IDs, tenant IDs, event timestamps (UTC), ingestion timestamps and expected inclusion.
3. Generate the same report twice with identical tenant, start/end instants, timezone, filters and software commit.
4. Compare normalized report data and source-record ID sets. If PDFs contain generated metadata, compare extracted content/data rather than raw PDF bytes.
5. Generate an adjacent non-overlapping window and verify boundary records are included exactly once according to the documented convention.
6. Attempt a cross-tenant report request and a request with missing tenant context; both must fail closed.
7. Trace each reported count/row back to its source IDs and verify that excluded records are absent.
8. Record report parameters, source IDs, output hashes, generator commit and operator identity.

### Pass criteria
- Repeated identical runs produce identical normalized data and source-record sets.
- Window boundaries and timezone are explicit and deterministic; adjacent windows do not silently double-count or omit records.
- Every report result is traceable to tenant-scoped source records.
- Missing or mismatched tenant context is rejected.
- Evidence contains input parameters, source IDs, normalized output comparison and report hashes.

## Evidence bundle checklist

For each drill, retain a dated evidence bundle containing:
- Drill ID, operator, approver, date/time and environment.
- CyberGuardian commit SHA, configuration summary and OS/kernel/filesystem where applicable.
- Redacted command output, logs, API responses and relevant screenshots.
- Input/output record IDs, queue counts, backup digests, report hashes or other reproducible measurements.
- Pass/fail result, deviations, incidents and remediation owner.
- Explicit statement of which physical/independent controls were actually exercised.

Do not include credentials, HMAC keys, client personal data or unredacted secrets in the evidence bundle or Git repository.
