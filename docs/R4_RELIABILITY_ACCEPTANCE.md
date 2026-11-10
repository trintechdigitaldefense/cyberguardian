# R4 Reliability, Audit, Fleet and Reporting Acceptance

**Target branch:** `main`  
**Status:** IN PROGRESS — not a release gate pass  
**Last reviewed:** 2026-11-10

R4 is the integration phase after R3 operator/service security acceptance. Each item below requires implementation, automated tests against the exact branch head, and restart/recovery evidence. A green Python matrix alone does not establish filesystem power-loss safety or client deployment readiness.

## Acceptance matrix

| Area | Implementation now present | Evidence / remaining work |
|---|---|---|
| Offline queue | JSONL queue with advisory locking, atomic replace, fsync, owner-only files, record/byte caps, overflow rejection preserving older pending events, content dedupe, ack-only removal, exponential retry, bounded flush, corrupt-record retention. Queue callbacks pass the stable queue record ID to the controller. | `tests/test_offline_queue.py` covers atomic-replace/fsync fault injection, process restart, partial acknowledgement, concurrent enqueue/flush and stable record IDs. A real network-partition/reconnect drill and Android/Termux filesystem validation remain. |
| Audit durability | SQLite audit index plus append-only JSONL hash chain, serialized append, fsync, chain verification, fail-closed extension, signed HMAC checkpoint export/verify and atomic restore helper. | `tests/test_audit_ledger.py` and `tests/test_audit_checkpoint_cli.py` cover tampering, truncated/partial append, concurrent writers, signed checkpoint verification, wrong-key rejection and clean-path restore. A restore drill on a separately provisioned instance and independent off-host immutable storage remain. |
| Issue memory | Locked atomic JSONL store, bounded active/archive retention, fail-closed malformed-record handling, tenant-bound fingerprints, verified request tenant context, object-level update authorization, tenant-only archive export and idempotent restore. | `tests/test_issue_memory.py` covers concurrent writers, archive capacity, tenant-separated findings, cross-tenant update denial, malformed/truncated input, private export permissions, overwrite/symlink refusal and idempotent restore. A formally approved retention schedule remains. |
| Fleet lifecycle | Tenant-filtered fleet response projects stale last-seen agents to offline, unknown timestamps to unknown, and preserves revoked/disabled states; configurable `CG_AGENT_STALE_AFTER_SECONDS` | `tests/test_fleet_lifecycle.py` and tenant-scoped API-level assertions in `tests/test_service_auth_scopes.py`; [run 42871748997](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42871748997) passed the stale/offline projection and tenant isolation tests. Signed registration heartbeat/reconnect now verifies last_seen refresh without duplicate inventory rows; cross-tenant registration is rejected; revoked credentials are rejected and the enrollment CLI can re-enroll the same asset with fresh API, identity and command secrets. Tests: `tests/test_agent_api_integration.py`, `tests/test_agent_enrollment.py`. Longer-lived multi-agent Compose lifecycle transitions and a physical reconnect exercise remain. |
| Client reports | Tenant-explicit weekly/scorecard fetch, mismatch/missing-source rejection, escaped PDF fields, tenant-bound PDF/CSV, atomic private output and formula-safe CSV cells. | `tests/test_weekly_client_report.py` covers tenant mismatch, missing tenant, generated PDF signature, output permissions and CSV injection. Live Compose authorization, source-record provenance and repeatable date-window evidence remain. |
| End-to-end workflow | R1/R2/R3 provide signed agent delivery, human gate, containment and operator audit foundations; gateway now stores idempotency responses transactionally for agent detection and command-result endpoints. | Integration tests exercise signed registration/reconnect, tenant-bound command polling, signed command-result reporting, replay response caching, and credential revocation. A single live Compose test covering detect → decision → stage → operator approve/reject → signed delivery → safe execution → correlated audit → tenant report is still outstanding. |

## Operational caveats

- The offline queue remains at-least-once transport. The gateway persists replay responses for `POST /v1/detections` and `POST /v1/agent/command-result`, keyed by tenant, asset, event digest, method and path; the endpoint's SQLite work and replay record share one transaction. Do not describe the entire distributed workflow as exactly-once: external audit-ledger writes and non-idempotent endpoints still require separate recovery/duplicate analysis.
- The local audit hash chain detects edits/truncation and accidental corruption, but a privileged attacker able to replace both application and ledger can rewrite it. Export signed checkpoints to an independently administered append-only destination.
- The issue-memory store has a bounded 2,000-record active set and a bounded append-only archive. The new `scripts/issue_archive.py` exports one tenant's archive to a private JSONL snapshot and restores only matching-tenant records without overwriting conflicting history. A formally approved retention schedule remains open.
- CI uses disposable runners and test data. It does not simulate physical power loss, damaged flash media, Android/Termux filesystem behavior, or real network partitions.
- Keep Client Mode enabled and all disruptive actions explicitly human-approved during pilot validation.

## Exit criteria

- [ ] Latest exact branch head, including the new audit export CLI, passes all six CI jobs on Python 3.10/3.11/3.12, Docker API, Compose and containment integration.
- [ ] Queue restart/reconnect tests prove pending records survive process restart and only acknowledged events are removed.
- [ ] Controller idempotency tests prove matching detection and command-result replays return the stored response, mismatched event digests fail closed, and the replay record is retained beyond ordinary retry windows.
- [ ] Fault injection covers truncated/corrupt queue and issue-memory files; recovery preserves evidence and fails closed.
- [ ] Audit chain survives gateway restart, detects tampering, and can be restored and verified from a consistent backup.
- [ ] Tenant A cannot view, update, export or infer Tenant B's issues, audit, fleet, actions or reports.
- [ ] Fleet enrollment, heartbeat, stale/offline transition, reconnect, revoke and re-enroll are covered end-to-end.
- [ ] PDF/CSV reports are reproducible, tenant-scoped, permission-checked and traceable to source records/time window.
- [ ] Supervised detect-to-report workflow passes with approval/rejection, signed delivery, safe execution, audit correlation and report verification.
- [ ] Operations docs cover backup/restore, queue overflow, audit verification/export, retention and incident recovery.

**Release rule:** R4 is not complete until every exit criterion is evidenced. R5's real 600-second soak and supervised pilot remain locked until then.


## Latest queue concurrency correction (2026-11-10)

Commit `ef1cc1efa3c1a0f408320c092568fc3681281ad8` moved the HTTP callback out of the queue's exclusive file lock. The flusher snapshots pending records, delivers them without holding the lock, then reacquires the lock and atomically reconciles acknowledgements/retry state against the latest queue contents. This preserves records enqueued while delivery is in progress. The existing regression test `test_enqueue_is_not_blocked_by_network_delivery` and the complete six-job CI pipeline passed in [run 42872872418](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42872872418).

The queue intentionally retains at-least-once transport semantics. For the two agent event endpoints above, the controller returns the stored response for a matching replay, preventing the corresponding SQLite business transaction from running twice. A crash can still repeat effects outside that transaction; keep the claim scoped to the protected endpoint transaction, not the entire workflow.


## Signed audit checkpoint workflow

The exporter now creates a signed checkpoint by default. Generate a dedicated random key outside the repository and application host, store it in the approved secret manager, and provide it to the export/verify process as `CG_AUDIT_CHECKPOINT_KEY_HEX` (at least 32 random bytes encoded as 64+ hexadecimal characters). Never commit the key or pass it as a command-line argument.

```bash
# Example key generation; store the output in a secret manager, not a tracked file.
python -c 'import secrets; print(secrets.token_hex(32))'

# Export a verified snapshot and adjacent .manifest.json HMAC manifest.
python scripts/export_audit_ledger.py --out /secure-independent-volume/cyberguardian-audit.jsonl

# Verify the manifest signature, snapshot digest, record count and hash chain.
python scripts/verify_audit_checkpoint.py --snapshot /secure-independent-volume/cyberguardian-audit.jsonl

# Restore to a clean instance's separate data path; existing files are protected.
python scripts/restore_audit_checkpoint.py \
  --snapshot /secure-independent-volume/cyberguardian-audit.jsonl \
  --destination /srv/cyberguardian-restore/audit_ledger.jsonl
```

The checkpoint uses HMAC-SHA256 (shared-key authentication), not a public-key signature. Keep the key and exported snapshot under independent administrative control. A restore drill must copy the snapshot into a clean test data directory, verify it with the key, and confirm that the gateway can read/continue the restored audit history without weakening fail-closed corruption checks.


The signed-checkpoint command-line regression test is `tests/test_audit_checkpoint_cli.py`. Full CI run [42873777649](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42873777649) passed all six jobs on commit `609b6ba5fbb235bc369f9d1c99f5916ecc83e689`, including 106 Python 3.11 tests and the production-mode Compose job.


Fleet transition regression coverage passed in [run 42874048743](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42874048743) on commit `96db82a2db04511bf5eb3e01b4ce816e9b8a6f0c`; all six CI jobs passed, including 107 Python 3.11 tests and production-mode Compose acceptance.


Issue archival regression tests: `tests/test_issue_memory.py` verifies that active-store eviction preserves the complete set of records in the archive, archive files are owner-only, and a full archive rejects new records without dropping the active issue. Full CI run [42874722338](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42874722338) passed all six jobs on `0612b5182e9d7a5b988989b8770054ceb9ab8478`, including the signed checkpoint restore CLI and 110 Python 3.11 tests.


A clean-instance restore helper is available as `scripts/restore_audit_checkpoint.py`. It verifies the HMAC manifest, snapshot digest, record count and chain before writing a separate destination atomically. It refuses an existing destination unless `--replace` is explicitly supplied. The test suite exercises the API and CLI restore paths; operational restore to an independently administered host is still required.
