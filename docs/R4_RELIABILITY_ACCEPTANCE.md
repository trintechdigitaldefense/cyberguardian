# R4 Reliability, Audit, Fleet and Reporting Acceptance

**Target branch:** `main`  
**Status:** IN PROGRESS — not a release gate pass  
**Last reviewed:** 2026-11-10

R4 is the integration phase after R3 operator/service security acceptance. Each item below requires implementation, automated tests against the exact branch head, and restart/recovery evidence. A green Python matrix alone does not establish filesystem power-loss safety or client deployment readiness.

## Acceptance matrix

| Area | Implementation now present | Evidence / remaining work |
|---|---|---|
| Offline queue | JSONL queue with advisory locking, atomic replace, fsync, owner-only files, record/byte caps, overflow rejection preserving older pending events, content dedupe, ack-only removal, exponential retry, bounded flush, corrupt-record retention. Queue callbacks pass the stable queue record ID to the controller. | `tests/test_offline_queue.py` covers atomic-replace/fsync fault injection, process restart, partial acknowledgement, concurrent enqueue/flush, stable record IDs, a real loopback TCP controller outage/reconnect after queue restart, and two separate tenant-bound agent queues. CI run `42915576796` passed. A physical network partition/reconnect drill and Android/Termux filesystem validation remain. |
| Audit durability | SQLite audit index plus append-only JSONL hash chain, serialized append, fsync, chain verification, fail-closed extension, signed HMAC checkpoint export/verify and atomic restore helper. | `tests/test_audit_ledger.py` and `tests/test_audit_checkpoint_cli.py` cover tampering, truncated/partial append, concurrent writers, signed checkpoint verification, wrong-key rejection and clean-path restore. A restore drill on a separately provisioned instance and independent off-host immutable storage remain. |
| Issue memory | Locked atomic JSONL store, bounded active/archive retention, fail-closed malformed-record handling, tenant-bound fingerprints, verified request tenant context, object-level update authorization, tenant-only archive export and idempotent restore. | `tests/test_issue_memory.py` covers concurrent writers, archive capacity, tenant-separated findings, cross-tenant update denial, malformed/truncated input, private export permissions, overwrite/symlink refusal and idempotent restore. A formally approved retention schedule remains. |
| Fleet lifecycle | Tenant-filtered fleet response projects stale last-seen agents to offline, unknown timestamps to unknown, and preserves revoked/disabled states; configurable `CG_AGENT_STALE_AFTER_SECONDS` | `tests/test_fleet_lifecycle.py`, `tests/test_service_auth_scopes.py`, `tests/test_agent_api_integration.py` and `tests/test_agent_enrollment.py` cover stale/offline projection, two separately credentialed agents in separate tenants, signed heartbeat/reconnect without duplicate inventory, per-agent command polling, cross-tenant denial, revocation and fresh-credential re-enrollment. Exact-head CI run `42915576796` passed. Physical multi-agent disconnect/reconnect and client-network lifecycle validation remain. |
| Client reports | Historical audit query over the verified append-only ledger; request-bound operator and tenant scope; explicit UTC `[start, end)` window; 500-record pages pinned to one ledger head; source event IDs and record hashes; fail-closed on invalid chain, missing tenant, invalid window or unavailable source. PDF includes historical activity rows/provenance plus clearly-labelled current monitoring snapshot figures. | `tests/test_historical_audit_reporting.py` covers exact start/end boundaries, tenant isolation, stable pagination despite concurrent append, missing authentication, invalid windows, tenant override and corrupt-ledger denial. `tests/test_dashboard_client_reporting.py` covers period semantics, source IDs/hashes, duplicate/mismatched provenance and PDF content. Exact-head CI run `42915576796` passed all 182 tests on Python 3.10, 3.11 and 3.12. Client review with synthetic data and operational source-data verification remain separate. |
| End-to-end workflow | R1/R2/R3 provide signed agent delivery, human gate, containment and operator audit foundations; gateway stores idempotency responses transactionally for agent detection and command-result endpoints. | **Automated live Compose acceptance passed** on commit `71396125e4f629fe1950396b9978034c8c98c00e`, Actions run [42906028038](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42906028038). The six-job run covers high-severity detection, decision creation, two tenant-scoped staged actions, operator approval and rejection, signed command delivery, rejected-command non-delivery, safe non-disruptive execution, command-result replay, correlated audit lookup and tenant weekly-report retrieval. Disruptive isolation is deliberately not executed in the shared Compose stack; firewall execution remains isolated to the containment namespace job. Multi-agent field operation and independent audit/report provenance drills remain separate operational evidence. |

## Operational caveats

- The offline queue remains at-least-once transport. The gateway persists replay responses for `POST /v1/detections` and `POST /v1/agent/command-result`, keyed by tenant, asset, event digest, method and path; the endpoint's SQLite work and replay record share one transaction. Do not describe the entire distributed workflow as exactly-once: external audit-ledger writes and non-idempotent endpoints still require separate recovery/duplicate analysis.
- The local audit hash chain detects edits/truncation and accidental corruption, but a privileged attacker able to replace both application and ledger can rewrite it. Export signed checkpoints to an independently administered append-only destination.
- The issue-memory store has a bounded 2,000-record active set and a bounded append-only archive. The new `scripts/issue_archive.py` exports one tenant's archive to a private JSONL snapshot and restores only matching-tenant records without overwriting conflicting history. A formally approved retention schedule remains open.
- CI uses disposable runners and test data. It does not simulate physical power loss, damaged flash media, Android/Termux filesystem behavior, or real network partitions.
- Keep Client Mode enabled and all disruptive actions explicitly human-approved during pilot validation.

## Exit criteria

- [x] Exact R4 candidate head `eee833045c5d4787d0740b273b9275e857776c46` passed all six CI jobs in [run 42915576796](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42915576796): 182 tests passed on Python 3.10/3.11/3.12, Docker API smoke, production Compose acceptance and nftables/iptables containment integration.
- [x] Queue restart/reconnect tests prove pending records survive process restart and only acknowledged events are removed; loopback TCP outage/reconnect simulation passed.
- [x] Controller idempotency tests prove matching detection and command-result replays return the stored response, mismatched event digests fail closed, and replay records are retained beyond ordinary retry windows.
- [x] Fault injection covers truncated/corrupt queue and issue-memory files; recovery preserves evidence and fails closed.
- [ ] Audit chain survives gateway restart, detects tampering, and can be restored and verified from a consistent backup on an independently administered clean instance.
- [x] Tenant A cannot view, update, export or infer Tenant B's issues, audit, fleet, actions or reports in automated integration tests.
- [x] Fleet enrollment, heartbeat, stale/offline transition, reconnect, revoke and re-enroll are covered end-to-end with two separately credentialed synthetic agents.
- [x] Historical PDF reporting is reproducible, tenant-scoped, and traceable to source event IDs/hashes and a pinned audit-ledger checkpoint; exact date-window acceptance tests passed in run 42915576796.
- [x] Supervised detect-to-report workflow passes in live Compose CI with approval/rejection, signed delivery, safe non-disruptive execution, command-result replay, audit correlation and tenant weekly-report retrieval (run 42906028038, commit `71396125e4f629fe1950396b9978034c8c98c00e`).
- [x] Operations docs cover backup/restore, queue overflow, audit verification/export, retention approval and incident recovery.
- [ ] Physical agent network partition/restart/reconnect drill and physical multi-agent disconnect/reconnect drill completed with evidence.
- [ ] Signed checkpoint transferred to independently administered storage, verified there, restored on a separately provisioned clean instance, and extended with a new audit event.
- [ ] Client data owner and authorized approver have signed the retention schedule in `docs/R4_RETENTION_APPROVAL.md`.

**Release rule:** R4 is not complete until every exit criterion is evidenced. R5's real 600-second soak and supervised pilot remain locked until then.


## Latest queue concurrency correction (2026-11-10)

Commit `ef1cc1efa3c1a0f408320c092568fc3681281ad8` moved the HTTP callback out of the queue's exclusive file lock. The flusher snapshots pending records, delivers them without holding the lock, then reacquires the lock and atomically reconciles acknowledgements/retry state against the latest queue contents. This preserves records enqueued while delivery is in progress. The existing regression test `test_enqueue_is_not_blocked_by_network_delivery` and the complete six-job CI pipeline passed in [run 42872872418](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42872872418).

The queue intentionally retains at-least-once transport semantics. For the two agent event endpoints above, the controller returns the stored response for a matching replay, preventing the corresponding SQLite business transaction from running twice. A crash can still repeat effects outside that transaction; keep the claim scoped to the protected endpoint transaction, not the entire workflow.


## Tenant-scoped issue archive export and restore

Export one tenant's archived issue history to a new private JSONL snapshot. The command refuses to overwrite an existing destination and reports a SHA-256 digest:

```bash
python3 scripts/issue_archive.py export \
  --tenant-id client-a \
  --out /secure-independent-volume/client-a-issues.jsonl
```

Restore the snapshot by merging records into the configured archive. The restore requires an explicit matching tenant, rejects truncated or cross-tenant records, preserves conflicting existing history, and is safe to repeat:

```bash
python3 scripts/issue_archive.py restore \
  --tenant-id client-a \
  --input /secure-independent-volume/client-a-issues.jsonl
```

Protect the snapshot and its destination directory as client data. The digest is an integrity aid, not a digital signature; store the snapshot and digest under the client's approved backup controls. An approved retention schedule is still required before production archival rotation.

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


## Live supervised Compose workflow acceptance (2026-11-10)

The full six-job CI run [42906028038](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42906028038) passed on exact commit `71396125e4f629fe1950396b9978034c8c98c00e`.

The Compose job starts the production-mode services with disposable credentials and an enrolled test agent, then verifies:

1. Two distinct high-severity detections produce tenant-bound decisions and human-gated isolation actions.
2. A request-bound operator assertion approves one action and rejects the other.
3. The approved isolation command is delivered with a valid per-agent signature; the rejected command is not delivered.
4. A separately queued `escalate` command is signed, delivered, and passed through the actual agent dispatcher as a non-disruptive action. The test does not execute the approved isolation command.
5. The agent command-result event is accepted; an identical event replay returns the stored response and replay marker.
6. The resulting command is correlated in the audit response and the tenant-scoped weekly report endpoint returns a non-empty report.

Python 3.11 completed with 171 passing tests. Python 3.10, 3.12, Docker API smoke, Compose and disposable nftables/iptables containment integration also passed. This is automated integration evidence, not a substitute for a physical network-partition/reconnect exercise, independent off-host audit restore, approved retention schedule, multi-agent reconnect validation or Android/Termux testing. R4 remains in progress until those operational exit criteria are signed off; R5 remains locked.

## Operational drill preparation (2026-11-10)

Runbooks and an explicit client approval record are available on the `r4-operational-drill-runbooks` branch:

- [R4 operational drill runbooks](R4_OPERATIONAL_DRILL_RUNBOOKS.md) define the offline partition/reconnect, independent audit backup and clean-instance restore, multi-agent physical reconnect, and report provenance/date-window procedures, including pass/fail criteria and required evidence.
- [R4 client data-retention approval](R4_RETENTION_APPROVAL.md) is intentionally **NOT APPROVED** until the client data owner and authorized approver complete and sign it. No retention periods have been assumed.

These documents prepare the operational acceptance work; they do not claim that a physical drill, independent off-host restore, or policy approval has occurred. R4 remains IN PROGRESS and R5 remains locked until dated evidence is reviewed and all exit criteria pass.


## Dashboard client PDF report centre (branch implementation; CI pending)

The dashboard now includes a **Client PDF Reporting Centre** on the r4-operational-drill-runbooks branch. An authenticated operator can generate an on-demand PDF assembled from the current tenant-scoped monitoring summary, fleet view, approval queue, remembered issues, recent audit/activity records and the gateway's existing weekly digest. The report translates common security terms into everyday language, explains what alerts do and do not prove, shows the human-approval setting, and states source and coverage limitations.

Implementation:
- dashboard/client_reporting.py builds the PDF in memory; it does not write client report content to the dashboard filesystem.
- GET /ops/reports/client.pdf requires an authenticated dashboard session and explicit tenant context. Each source request uses a request-bound operator assertion and tenant identity. If a source is unavailable or invalid, the endpoint fails closed and does not return a partial report.
- The dashboard exposes a generate/download control; the response is marked no-store and served as a PDF attachment.
- tests/test_dashboard_client_reporting.py covers PDF generation, glossary translation, tenant mismatch rejection and unknown metric handling.

**Scope limitation:** this first version is a live snapshot plus the gateway's existing weekly digest. The audit/activity section is limited to the latest 100 records returned by the API. It does not yet provide arbitrary start/end date filters, a complete historical event export, scheduled delivery, or a formal client retention workflow. Do not describe it as exhaustive historical reporting. CI must pass on the exact PR head before treating the feature as accepted.



## Historical client PDF reporting implementation candidate (2026-11-10)

The R4 branch now implements the historical activity query rather than filtering the legacy latest-100 audit response.

- `GET /v1/audit/history` reads the append-only hash-chained audit ledger under a shared ledger lock and verifies the complete chain before returning data.
- The API requires request-bound dashboard operator authentication and a tenant context. Records are included only when the tenant is explicit in the operator audit context or can be resolved through the registered asset / pending-action ownership checks. Unattributable records are excluded; they are never assigned to a client by default.
- Reporting timestamps must be timezone-aware ISO-8601 values. The API normalizes to UTC and applies the documented half-open interval **[start, end)**: start inclusive, end exclusive.
- Pagination is limited to 500 rows per page and pins all pages to one verified ledger hash. Concurrent appends cannot shift the report's offsets. The dashboard fails closed if the snapshot changes, a page is missing, counts disagree, or more than 10,000 records are requested in one PDF.
- Every historical row carries its audit event ID, timestamp, tenant ID and record hash. The PDF includes source record IDs and the checkpoint head so a client/operator can trace the activity.
- The PDF explicitly distinguishes historical activity from current fleet/risk/gate snapshots and the existing weekly digest. It does not claim that the other snapshot metrics are historical time-series data.

New acceptance tests:
- `tests/test_historical_audit_reporting.py`: exact boundary inclusion/exclusion, cross-tenant exclusion, stable snapshot pagination, missing operator assertion, invalid/naive/reversed periods, tenant query override and corrupted ledger denial.
- `tests/test_dashboard_client_reporting.py`: period metadata, source ID inclusion, duplicate ID rejection, cross-tenant record rejection, out-of-window rejection and source-count mismatch.

**Status:** implementation and tests committed to the R4 candidate branch; the exact new head still requires the complete CI matrix. Do not check the historical reporting exit criterion until that CI run passes and a client-facing PDF has been reviewed with synthetic tenant data.


## Exact-head automated acceptance evidence (2026-11-10)

Candidate eee833045c5d4787d0740b273b9275e857776c46 passed GitHub Actions run [42915576796](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42915576796). All six jobs succeeded: Python 3.10/3.11/3.12 (182 tests each), Docker API build/health, production-mode Compose acceptance, and disposable nftables plus iptables containment integration. The new historical audit and PDF tests and loopback TCP queue outage/reconnect tests are included in this run. This evidence does not represent physical client-network drills, independent off-host restore, or client retention approval.
