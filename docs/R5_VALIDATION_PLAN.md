# CyberGuardian R5 Validation Plan

**Status:** PREPARATION ONLY — R5 execution is blocked until the R4 acceptance matrix is complete and signed off.
**Target:** a reproducible, supervised R5 candidate on the exact commit intended for release.

This document is a test plan, not evidence that a field exercise or soak test has run. CI, a local container, and a physical client-like environment are separate evidence classes and must not be conflated.

## 1. R4 release gate (must pass before R5 execution)

Record evidence against the exact candidate commit for every item:

- [ ] Offline queue: controlled network partition, at least three uniquely identified synthetic events, agent restart while disconnected, reconnect, acknowledgement-only removal, and duplicate-safe controller processing.
- [ ] Audit durability: signed checkpoint exported to independently administered storage, verified there, restored to a clean instance, and extended by a new synthetic event without changing prior history.
- [ ] Fleet lifecycle: at least two agents, physical/network disconnect and reconnect, stale/offline transition, heartbeat recovery without duplicate inventory, credential revocation and fresh re-enrollment.
- [ ] Client PDF reporting: authenticated tenant-scoped generation, source failure closed, tenant mismatch denied, deterministic date-window and provenance evidence, accurate missing-data labels and plain-language explanations.
- [ ] Retention: client-authorized schedule signed by the required data owner and approver. Software record caps are not retention periods.
- [ ] Operations documentation: backup/restore, queue overflow, audit verification/export, incident recovery, client data handling and operator permissions reviewed.
- [ ] All automated CI jobs pass on the exact head SHA. Record run URL, job results, test counts and artifacts.

For each physical drill retain a redacted evidence bundle with operator, approver, UTC timestamps, commit SHA, OS/kernel/filesystem, configuration, commands, queue counts or hashes, event/source IDs, output digests, pass/fail and deviations. Never include client personal data, credentials, signing keys or secrets.

## 2. R5 genuine 600-second stability test

Run only after R4 sign-off, against a disposable isolated environment and synthetic data. Do not run on a client network.

### Required protocol

1. Record candidate commit SHA, image digests, Python version, OS/kernel, filesystem, device model, CPU/memory, storage free space, configuration fingerprint and UTC start time.
2. Start the full supported service set and at least two uniquely credentialed agents. Confirm health, tenant separation and baseline resource measurements.
3. Run continuously for **600 seconds** using a monotonic clock. Sample service health, process restarts, CPU, resident memory, open file descriptors, disk use, queue depth/bytes, event delivery latency, error counts and audit-chain verification.
4. During the run, generate bounded synthetic monitoring events and safe non-disruptive workflows. Include a controlled short controller outage only if the R4 queue drill has passed; do not execute host isolation or other disruptive actions.
5. Verify all generated event IDs, tenant ownership, expected acknowledgements, absence of unexplained duplicates, no lost queued records, and audit-chain integrity.
6. Capture samples at least every 10 seconds and preserve raw machine-readable results, service logs, environment metadata and final summary.
7. Repeat the same run after a clean restart if the first run passes.

### Pass criteria

- At least 600 seconds of measured elapsed time, not a sleep-only placeholder.
- No unplanned service or agent restart, crash, deadlock, unbounded queue growth or unexplained event loss.
- No cross-tenant data or command visibility.
- All expected synthetic events accounted for; retries and duplicate behavior match documented semantics.
- No audit-chain verification failure.
- Resource use remains within documented limits and does not show sustained uncontrolled growth.
- Every failure is retained and reported; a rerun does not overwrite failed evidence.

Any missing telemetry, shortened duration, unexplained restart, lost event, cross-tenant observation or integrity failure is a failed run. Do not convert a failed or incomplete run into a pass by rerunning without preserving the original evidence.

## 3. Termux / Ubuntu compatibility validation

Validate separately on the actual supported Android device and its Termux/Ubuntu environment. A GitHub Linux runner is not equivalent.

Record Android version, device architecture, Termux version/source, Ubuntu userspace version, Python and pip versions, kernel, filesystem and storage paths. Validate:

- Installation from a clean clone using documented commands.
- Dependency installation and native package availability for the device architecture.
- Start, status, stop, restart and upgrade paths.
- Data-directory permissions and secret-file permissions.
- Queue locking, atomic replacement and fsync behavior on the actual filesystem.
- Process restart with pending offline events and reconnect acknowledgement.
- SQLite/audit ledger read, append, verification, backup and restore.
- Service lifecycle under Android backgrounding, battery restrictions and network changes.
- Recovery from interrupted installation and safe rollback.

Do not claim Android/Termux support for a feature until it has been exercised on the named device/filesystem combination. Document unsupported Android restrictions and operational workarounds.

## 4. Final security review

Review and attach evidence for:

- Authentication, session expiry/revocation, CSRF and role enforcement.
- Tenant isolation on every read, write, export, report, audit and agent lifecycle endpoint.
- Service-to-service least privilege and denied cross-service credential access.
- Secret generation, minimum strength, storage permissions, rotation and leak scanning.
- Agent identity, signed registration, command signatures, replay handling and credential revocation.
- Dashboard security headers, trusted proxy configuration, TLS/cookie settings and origin policy.
- File permissions, path handling, symlink/overwrite protections and backup confidentiality.
- Installation, upgrade, rollback, recovery and least-privilege runtime accounts.
- Dependency vulnerabilities, pinned dependencies, container image provenance and CI workflow permissions.
- Outstanding findings with severity, evidence, owner, remediation and retest result.

No unresolved critical/high finding may be waived silently. Any accepted residual risk requires a named approver, rationale, scope and expiry/review date.

## 5. Release handover evidence

The release candidate is eligible only after:

- R4 sign-off and all R5 tests above pass on the same candidate commit.
- Exact commit SHA, release tag, CI run links and test artifacts are recorded.
- Installation and upgrade instructions are tested from a clean clone.
- Configuration examples contain placeholders only; no live secrets are committed.
- Backup/restore and rollback instructions are independently followed.
- Known limitations, supported platforms and client operational prerequisites are documented.
- Final report clearly separates CI evidence, lab evidence and physical device evidence.

**Release rule:** Do not label CyberGuardian client-ready or publish a production release while any required acceptance item is incomplete. The user's Android/Termux clone test remains an additional field-validation step after the candidate handover, not something GitHub CI can certify.
