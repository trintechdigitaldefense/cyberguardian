# CyberGuardian R4 pilot release assessment

**Decision: NO-GO for client pilot and unattended 24-hour operation.**

Assessment date: 2026-11-18  
Assessment scope: R4 branch and current repository/CI evidence  
Target branch: `r4-operational-drill-runbooks`  
Feature under review: PR #14, `r4-transactional-outbox`

## Evidence reviewed

- R4 changes PRs #9–#13 are present on the R4 branch. PR #14 is a separate
  feature branch/PR and has not been merged.
- PR #14 adds a reusable SQLite transactional operation/outbox foundation:
  tenant-scoped idempotency, request fingerprints, atomic same-database
  operation/outbox commits, ordered at-least-once dispatch, worker leases,
  retry scheduling, stable event IDs and a durable reconciliation-required
  state.
- Exact-head GitHub Actions run
  [44413431360](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/44413431360)
  passed all six jobs on
  `976a960947f2b75fd8d7eb6bf7e662219a3cf445`:
  Python 3.10, 3.11, 3.12, Docker API, Compose stack and containment integration.
- The automated outbox suite includes rollback after exception and hard
  subprocess exit, same-key replay, request-fingerprint conflict, tenant
  separation, concurrent duplicate submissions and worker claims, lease expiry,
  ordered delivery, retry and receiver-side stable-ID deduplication simulation.
- The existing hash-chained JSONL audit ledger remains separate from SQLite.
  PR #14 does not yet include a duplicate-aware stable-ID ledger append adapter
  or a supervised dispatcher/recovery service.
- Existing live pilot middleware, agent command execution and file-backed
  operation paths have not yet been migrated to the new outbox.
- No physical network-outage, power-loss, multi-device, independent audit
  restore, retention or incident-response drill has been executed as part of
  this assessment.

## Decision by deployment mode

| Deployment mode | Decision | Reason |
|---|---|---|
| Developer/CI validation | PASS for the tested code paths | Six CI jobs pass on the cited exact commit. |
| Controlled owner lab | CONDITIONAL | May proceed only in an isolated, non-client environment with human supervision and non-disruptive tests. |
| Supervised client pilot | NO-GO | Live operation paths are not fully integrated with the outbox; physical client-readiness evidence is absent. |
| Unattended 24-hour service | NO-GO | Availability, restart recovery, monitoring, backup/restore, on-call response and physical network recovery have not been demonstrated. |
| General production deployment | NO-GO | End-to-end transactional, operational, retention and support gates remain open. |

## Mandatory gates before reconsideration

1. Integrate durable operation/idempotency records into each approved live action
   path, preserving human approval and signed/expiring command envelopes.
2. Add a stable-ID duplicate-aware adapter from the outbox to the hash-chained
   audit ledger, plus a supervised worker with restart recovery, alerting,
   bounded retry policy and operator reconciliation.
3. Classify every operation's side-effect boundary. Do not automatically replay
   a remote/device action when its outcome is ambiguous and the downstream
   system cannot enforce idempotency or report operation status.
4. Migrate or explicitly exclude file-backed state paths; do not claim they share
   SQLite atomicity.
5. Pass the physical drill matrix in
   `docs/R4_CLIENT_READINESS_DRILLS.md`, with retained evidence and independent
   witness review.
6. Obtain client approval for retention, backup location, recovery objectives,
   incident contacts, support coverage and service-level commitments.
7. Resolve release metadata/version consistency and produce a signed release
   manifest for the exact reviewed commit.

## Release boundary

Passing CI establishes regression evidence for the tested workflows. It does
not establish production readiness, client network readiness, 24-hour
availability, successful physical recovery, or a service-level guarantee.
Reassess only after the mandatory gates above are evidenced. Until then, do not
market R4 as an unattended 24/7 managed service or authorise a client production
deployment.
