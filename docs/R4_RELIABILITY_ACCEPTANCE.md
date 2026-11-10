# R4 Reliability, Audit, Fleet and Reporting Acceptance

**Branch:** `r2-1.6.0-security`  
**Status:** IN PROGRESS — not a release gate pass  
**Last reviewed:** 2026-11-10

R4 is the integration phase after R3 operator/service security acceptance. Each item below requires implementation, automated tests against the exact branch head, and restart/recovery evidence. A green Python matrix alone does not establish filesystem power-loss safety or client deployment readiness.

## Acceptance matrix

| Area | Implementation now present | Evidence / remaining work |
|---|---|---|
| Offline queue | JSONL queue with advisory locking, atomic replace, fsync, owner-only files, record/byte caps, overflow rejection preserving older pending events, content dedupe, ack-only removal, exponential retry, bounded flush, corrupt-record retention | `tests/test_offline_queue.py`; CI run [42869693720](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42869693720) passed all six jobs on `ae1126fdd0cd6cf3b303f1155b33709d9aef3118`. Add injected crash/partial-write and real reconnect tests in isolated environment. |
| Audit durability | Existing gateway SQLite audit plus a separate append-only JSONL hash chain; serialized append, fsync, chain verification, fail-closed extension on corruption; CLI verifier | `tests/test_audit_ledger.py`, gateway integration in `tests/test_service_auth_scopes.py`, `scripts/verify_audit_ledger.py`. Earlier CI run [42870539504](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42870539504) passed on `437f740ebb8c769947d74d98c73ecf613eaf04bb`. Later verifier-lock and fleet changes require latest-head CI. Add remote signed checkpoints/export and restore/restart verification. |
| Issue memory | JSONL issue store now uses a process lock and atomic fsync/replace, owner-only file permissions, bounded retention, fail-closed handling of malformed rows | `tests/test_issue_memory.py`; initial atomic-write tests were included in CI run [42870707293](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42870707293), 93 tests passed. The later malformed-record fail-closed change needs latest-head CI. Verify caller tenant association and object-level update authorization during full workflow review. |
| Fleet lifecycle | Tenant-filtered fleet response projects stale last-seen agents to offline, unknown timestamps to unknown, and preserves revoked/disabled states; configurable `CG_AGENT_STALE_AFTER_SECONDS` | `tests/test_fleet_lifecycle.py`; latest CI is pending at the time of this document. Add API-level lifecycle/revocation tests and stale-agent reconnect transitions. |
| Client reports | PDF generation requires explicit tenant, requests tenant-scoped weekly and scorecard data, rejects cross-tenant response, aborts on missing data, escapes dynamic scorecard fields | `tests/test_weekly_client_report.py`; CI run [42870707293](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42870707293) passed all six jobs and 93 tests on `2c1caf3eb4f375a409808ab06637b9b8ab35e5ce`. Add PDF content/provenance/export-permission tests against a live Compose tenant. |
| End-to-end workflow | R1/R2/R3 provide signed agent delivery, human gate, containment and operator audit foundations | Full R4 supervised detect → decide → stage → approve/reject → signed delivery → safe execution → audit → tenant report acceptance remains outstanding. |

## Operational caveats

- The offline queue provides at-least-once delivery semantics: a response lost after server acceptance can cause a retry. Server-side idempotency for all telemetry endpoints is still required before claiming exactly-once delivery.
- The local audit hash chain detects edits/truncation and accidental corruption, but a privileged attacker able to replace both application and ledger can rewrite it. Export signed checkpoints to an independently administered append-only destination.
- The issue-memory store is bounded to 2,000 records; retention policy and archival/export are not yet implemented.
- CI uses disposable runners and test data. It does not simulate physical power loss, damaged flash media, Android/Termux filesystem behavior, or real network partitions.
- Keep Client Mode enabled and all disruptive actions explicitly human-approved during pilot validation.

## Exit criteria

- [ ] Latest exact branch head passes all six CI jobs on Python 3.10/3.11/3.12, Docker API, Compose and containment integration.
- [ ] Queue restart/reconnect tests prove pending records survive process restart and only acknowledged events are removed.
- [ ] Fault injection covers truncated/corrupt queue and issue-memory files; recovery preserves evidence and fails closed.
- [ ] Audit chain survives gateway restart, detects tampering, and can be restored and verified from a consistent backup.
- [ ] Tenant A cannot view, update, export or infer Tenant B's issues, audit, fleet, actions or reports.
- [ ] Fleet enrollment, heartbeat, stale/offline transition, reconnect, revoke and re-enroll are covered end-to-end.
- [ ] PDF/CSV reports are reproducible, tenant-scoped, permission-checked and traceable to source records/time window.
- [ ] Supervised detect-to-report workflow passes with approval/rejection, signed delivery, safe execution, audit correlation and report verification.
- [ ] Operations docs cover backup/restore, queue overflow, audit verification/export, retention and incident recovery.

**Release rule:** R4 is not complete until every exit criterion is evidenced. R5's real 600-second soak and supervised pilot remain locked until then.
