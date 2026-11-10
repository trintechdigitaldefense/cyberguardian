# CyberGuardian Roadmap — 1.6.0 Security Release

**Repository:** https://github.com/trintechdigitaldefense/cyberguardian  
**Primary branch:** main  
**Active hardening branch:** r2-1.6.0-security  
**Roadmap status reviewed:** 2026-11-10  
**Latest verified R4 code commit:** `49987f6fecedd5718a1a2f53bea449fefc1ae7f4` (nonblocking offline queue delivery, restart/reconnect tests, and HMAC-signed audit checkpoint export/verification CLI; all six CI jobs passed).  
**Latest full CI:** [run 42873367469](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42873367469) passed all six jobs on `49987f6fecedd5718a1a2f53bea449fefc1ae7f4`: Python 3.10/3.11/3.12 (105 tests in Python 3.11), Docker API build/container smoke, disposable containment integration, and production-mode Compose acceptance.  
**R3 code-test baseline:** `61252a951cdbbf23f9d01a78f759f4e4e25b7807` — 62 tests passed.
**Latest R2 code commit with passing CI:** 10a375c4d0da37953a826baf69986de794668c4f

This roadmap preserves the original eight product phases and adds a release-readiness gate. A phase is not complete merely because a module or documentation entry exists: completion requires code on GitHub, tests passing against the same commit, and evidence for the phase acceptance criteria.

## Executive status

- main is at cf4832d1e36dd8139aaac3df7750386c482ff34b.
- r2-1.6.0-security is 64 commits ahead of main, with no commits behind it.
- R2 now includes process identity evidence propagation, PID/start-time validation, pidfd-bound signalling where supported, strict IP parsing, controller recovery allowlisting, dual-stack firewall handling, verified nftables rule activation, corrupt-marker fail-closed recovery, and human approval for disruptive playbook actions. CI on commit `10a375c4d0da37953a826baf69986de794668c4f` passed Python 3.10/3.11/3.12, all 47 automated tests, compilation, Docker API smoke, and the privileged containment-integration job. The integration job exercised real nftables and iptables/ip6tables rules in separate disposable network namespaces, including process identity checks, dual-stack blocking, controller recovery, idempotency, rollback, unrelated-rule preservation, and injected partial-rule failures (Actions run [42516793251](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42516793251)).
- Do not merge R2 into main yet. R0 and R1 code gates passed on commit `786b628`: Python 3.10/3.11/3.12, 12 automated tests, compilation, Docker build and container `/health` smoke all passed in Actions run [42511953408](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42511953408).
- Core agent, containment, offline queue, identity, decision-service, dashboard, and startup/status/stop files are tracked on the R2 GitHub branch. Their presence does not mean their security acceptance tests are complete.
- docs/TEN_MINUTE_TEST_REPORT.md records 16 checks passing in 7 seconds, not a ten-minute/600-second test. This is a short smoke-check report, not a completed ten-minute soak test.
- R0-R3 engineering gates are complete on the security branch. R4 is in progress: the offline queue has been hardened and CI-tested, while durable audit/action-history, fleet lifecycle, reporting/export and end-to-end workflow acceptance remain. R5 isolated 600-second soak and supervised pilot acceptance remain open. The product is not yet client-ready.

## Original eight phases

| Phase | Product area | Current assessment | Exit criteria |
|---|---|---|---|
| 1 | API Gateway | Implemented foundation; release-blocking packaging/integrity/CI issues remain on R2 | Clean clone assembles gateway deterministically; checksum and source completeness verified; API imports and /health returns 200; Docker build and container smoke pass |
| 2 | Decision Engine | Existing risk scoring/playbook decision service; service authentication and durable decision history need verification | Authenticated service-to-service calls; tenant-scoped decisions; documented scoring/playbook tests; durable decision and action history |
| 3 | Linux Agent | Agent and polling flow exist; signed-command enforcement must be proven end-to-end | Per-agent identity; signed, expiring, single-use commands; replay and wrong-asset rejection; safe heartbeat/enrollment; reconnect tests |
| 4 | Containment Engine | Linux containment and rollback acceptance passed in disposable namespace CI; Android/Termux profile validation remains in R5 | PID plus process-start-time validation; strict target checks; dedicated firewall chains; safe IPv4/IPv6 validation; controller recovery path; verified rollback; isolated-VM and mocked tests |
| 5 | Dashboard | Operator dashboard exists; authentication hardening remains incomplete | Strong password hashing; persistent expiring/revocable sessions; Secure/HttpOnly/SameSite cookies; CSRF protection; login throttling; operator attribution; role checks |
| 6 | Fleet Management | Basic registration, inventory, and last-seen functionality exist | Tenant-safe enrollment and inventory; unique device identity; stale/offline states; lifecycle/revocation; bounded discovery; multi-agent integration tests |
| 7 | Audit & Compliance | Audit trail and action history exist | Durable append-only or tamper-evident audit; actor/tenant/asset/approval/command correlation; retention/export; denied and failed action records; integrity tests |
| 8 | Reporting | Weekly digest/scorecard foundations exist | Reproducible report generation; verified data provenance; PDF/CSV export tests; time-zone and date-window correctness; report access controls |

## Release-readiness phase (required before a client pilot)

This is a cross-cutting gate, not a replacement for the eight product phases.

### R0 — Gateway and Docker build (COMPLETED)

**Verified code commit:** `3a2f9a393f4e86789823035bbaab0cec430449ca`  
**CI evidence:** [run 42510671312](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42510671312)

- Restored the corrupted final `gateway_z/05.txt` fragment from the verified `main` version.
- Made the six-part `gateway_z` source canonical; added strict chunk, decompression, syntax, checksum and size validation.
- Added portable runtime paths and corrected Docker's working directory.
- Made dependency installation fail closed and added gateway regression tests.
- Python 3.10/3.11/3.12 passed; four tests passed; compile, Docker build and container health smoke passed.

### R1 — Signed commands and agent identity (COMPLETED)

**Verified code commit:** `786b6283562ddd98b601142e33c4624a13a85b50`  
**CI evidence:** [run 42511953408](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42511953408)

- Agent verifies signed command envelopes before execution and rejects invalid signatures, expired commands, weak/missing nonces, wrong asset/tenant and unapproved disruptive actions.
- Controller signs commands with per-agent command secrets and binds the signature to command ID, tenant, asset, action, target, full parameters, approval reference, nonce and expiry.
- Agent persists consumed command IDs/nonces in a SQLite replay ledger.
- Per-agent API keys, identity secrets and command secrets are provisioned by `scripts/enroll_agent.py`; rotation and revocation are supported.
- API middleware scopes agent credentials to their enrolled asset/tenant and agent-only endpoints; admin/fleet endpoints are rejected.
- Registration and heartbeat use signed per-agent identity.
- Fixed command-poll SQLite audit locking by writing audit events after the command transaction commits.
- Added tests for command signing, replay, enrollment, rotation, revocation, tenant isolation, command delivery and result reporting.
- Python 3.10/3.11/3.12 passed; 12 tests passed; compile checks, Docker build and container health smoke passed.

R1 code and automated acceptance tests are complete. Real device provisioning and field verification remain part of R5 pilot acceptance.

### R2 — Complete containment and recovery safety (COMPLETED — Linux CI integration)

**Verified code commit:** `10a375c4d0da37953a826baf69986de794668c4f`; Actions run [42516793251](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42516793251). Python 3.10/3.11/3.12 passed, 47 automated tests passed, Docker API smoke passed, and the privileged integration job successfully exercised both nftables and iptables/ip6tables in disposable network namespaces.

Implemented and covered by automated tests:
- Process actions require command-line or start-time evidence; PID start-time mismatch, hint mismatch and unreadable proc identity fail closed.
- Agent inventory captures process start time and the decision service passes that identity evidence to the kill action.
- pidfd-bound signalling is used where supported; tests exercise the pidfd path.
- IP parsing rejects invalid, loopback, unspecified, multicast and link-local targets.
- Isolation refuses to proceed without a resolvable controller recovery address.
- nftables and iptables fallback paths include controller recovery allowlisting and dual-stack handling; isolation does not grant general DNS or established-session egress.
- Firewall rules are checked after insertion with token-boundary matching (so an address such as `192.0.2.1` cannot be mistaken for `192.0.2.10`). nftables tables require a CyberGuardian ownership marker before adoption or deletion.
- Recovery intent is persisted before firewall changes. Missing first-run markers are handled separately from corrupt/unreadable markers; a failed final marker update leaves the pending recovery record.
- Disruptive playbook actions (kill, isolate, block) remain human-approved. An arbitrary `allowlist_id` string is not accepted as authorization; a real tenant-scoped policy/approval service is required before any automatic disruptive allowlisting is introduced.

R2 Linux acceptance is complete. The CI integration job runs the harness in disposable network namespaces for both nftables and iptables/ip6tables and verifies real process termination, IPv4/IPv6 blocking, controller recovery, idempotency, normal rollback, preservation of unrelated firewall objects, and recovery after injected partial-rule failure.

Remaining environment-specific validation is part of R5: repeat the supervised checks on the actual supported Android/Termux-Ubuntu device/kernel profile, document pidfd/kernel availability, and confirm the device's firewall backend and privileges. Do not run destructive tests on a client or production host.

### R3 — Complete operator and service security (COMPLETED)

**Latest full CI evidence:** [run 42867381433](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42867381433) passed all six jobs on commit `1565851b4675591ef226b6d61078b332a6aead90`: Python 3.10/3.11/3.12, Docker API build/container smoke, disposable containment integration, and production-mode Docker Compose acceptance. The CI suite includes the operator provisioning CLI and tests.

Implemented and validated:
1. **Operator identity:** dashboard backend mints HMAC-SHA256 request-bound assertions only from persistent server-side sessions. Gateway verifies signature, 60-second freshness, 5-second future skew, nonce replay, method/path and tenant. Verified subject/role/tenant/request ID are bound to gateway audit writes.
2. **Audit attribution:** verified operator context is propagated to existing audit events; operator request start/completion records are written, and verified authorization denials are attributed. Tests verify subject, role and tenant details persist.
3. **Service least privilege:** administrator, dashboard, NAD, decision-service and operator-assertion secrets are separate, independently generated, 32+ byte and production-validated. Dashboard and NAD containers do not receive the administrator credential.
4. **Default-deny scopes:** dashboard service is limited to the explicit dashboard route/method allowlist and requires a valid operator assertion in production. NAD is limited to `POST /v1/detections`. Agent credentials remain per-asset/per-tenant. Decision service rejects missing or invalid internal credentials.
5. **Tenant isolation:** authenticated tenant is propagated into gateway query filters; mismatched query/body tenant overrides are rejected; fleet, gate, audit, feedback and issue list responses are filtered; rollback, approval/rejection and benign-feedback object IDs are checked against tenant ownership. Cross-tenant denials are audited. Reporting endpoints expose tenant filters in their API schema.
6. **Dashboard security:** login/session persistence, PBKDF2 password hashes, CSRF on mutations/logout, role enforcement, Secure/HttpOnly/SameSite cookies, strict CSP without `unsafe-inline`, external assets, output escaping, HSTS with secure-cookie mode, trusted-proxy-aware client IP extraction and bounded login-attempt retention.
7. **Production configuration:** API rejects missing, weak or reused secrets and admin-key/credential-store mismatch. Dashboard and NAD validate their own workload credentials. Compose keeps decision service internal and binds host API/dashboard ports to loopback.
8. **Operator onboarding and operations:** `scripts/manage_dashboard_user.py` provisions tenant-scoped admin/operator/analyst/viewer accounts using interactive passwords and PBKDF2 hashes. [R3 production operations](R3_PRODUCTION_OPERATIONS.md) documents independent secrets, rotation, TLS proxy setup, onboarding, backup and restore.
9. **Full Compose acceptance:** production-mode Compose CI builds/starts API, dashboard, decision service and NAD; exercises login, invalid CSRF, secure cookies/HSTS, dashboard proxy calls, audit attribution, client-mode authorization, logout/session revocation, workload credential separation, NAD detection scope and decision-service authentication.

R3 is accepted for the engineering roadmap. This is engineering/CI acceptance, not client-network certification. Keep the branch isolated from `main`; proceed to R4.

### R4 — Reliability, audit, and reporting integration

- Test offline queue durability, bounded overflow behaviour, atomic writes, locking, deduplication, retry/backoff, and acknowledged delivery.
- Verify durable audit/action history across restart and tenant boundaries.
- Verify fleet lifecycle, stale-agent status, report accuracy, and export permissions.
- Run the end-to-end supervised workflow: detect → decide → stage → approve/reject → signed delivery → execute safely → audit → report.

### R5 — Pilot acceptance

- Fresh clone and documented install succeed.
- API, decision service, dashboard, and one Linux agent pass health checks.
- Full operator-approved workflow succeeds in an isolated pilot environment.
- A real 600-second test records start/end timestamps, duration of at least 600 seconds, exact tested commit SHA, each test result, logs, resource/stability observations, and failures. Short smoke checks must be labelled as smoke checks.
- No unresolved critical/high security findings; client scope, authorization, rollback, retention, and incident contacts are documented.
- Pilot remains supervised; disruptive actions require explicit human approval by default.

## R4 implementation progress (2026-11-10)

**Latest verified R4 code checkpoint:** commit `1ce29a6910908d4114e49078ecff413428523ae8`; [run 42871748997](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42871748997) passed all six CI jobs and 99 Python tests.

The reliability work now covers:

- **Offline queue:** concurrent writer/flusher locking, atomic replace + fsync, owner-only permissions, record/byte caps, overflow rejection preserving older pending events, content dedupe, acknowledgement-only removal, bounded exponential backoff, bounded flush and corrupt-record retention. The queue lock is released during HTTP delivery so new events are not blocked by slow network calls.
- **Audit:** a separate append-only SHA-256 hash chain receives gateway audit writes. Chain verification, tamper detection, and consistent verified snapshot export are implemented. HMAC-SHA256 signed checkpoint manifests now have an export-by-default CLI and a separate verification CLI; wrong keys, altered snapshots and corrupt chains fail closed. Independent off-host storage and clean-instance restore drill remain.
- **Issue memory:** locked read/modify/write, atomic fsync/replace, owner-only permissions, bounded retention and fail-closed handling of malformed JSON.
- **Fleet lifecycle:** tenant-scoped dashboard fleet results project stale agents to offline and missing timestamps to unknown, while preserving revoked/disabled states.
- **Reporting:** weekly client reports require an explicit tenant and tenant-scoped source requests; optional CSV scorecard export is atomic, owner-only and protected against spreadsheet formula injection.

The latest 105-test Python 3.11 CI run validates queue concurrency/restart/reconnect, signed audit checkpoint verification and tamper rejection, audit chain, issue store, fleet projection and tenant-scoped PDF/CSV request/export logic. Subsequent audit snapshot-export CLI and documentation changes are awaiting CI on the latest branch head. These are code-level checks, not physical power-loss or Android/Termux filesystem fault-injection tests.

See [R4 reliability acceptance](R4_RELIABILITY_ACCEPTANCE.md) for the detailed matrix. **R4 remains in progress:** independent off-host checkpoint storage and clean-instance restore/restart drill, issue retention/archive policy, fleet heartbeat/reconnect/revoke transitions, live Compose report export permissions, and the supervised detect-to-report workflow remain. R5 stays locked until R4 acceptance is complete.

## Immediate work order

R0-R3 engineering gates are complete on the security branch. R4 reliability, audit, fleet and reporting integration is now active; the offline queue slice has passed its six-job CI pipeline. Continue R4 before R5. Keep the security branch isolated from `main`; do not merge or call the product client-ready until the complete R4/R5 gates pass.

## GitHub delivery rules

- Every logical change must be committed and pushed to r2-1.6.0-security (or a focused child branch) with a meaningful commit message.
- Update this roadmap and the changelog when phase status changes.
- Attach test evidence to the commit/PR and identify the exact SHA tested.
- Do not force-push, do not commit secrets, and do not merge failed or unverified builds.
- Keep main stable; merge only through a reviewed PR after required CI checks pass.
