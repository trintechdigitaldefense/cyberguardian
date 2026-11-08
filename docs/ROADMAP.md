# CyberGuardian Roadmap — 1.6.0 Security Release

**Repository:** https://github.com/trintechdigitaldefense/cyberguardian  
**Primary branch:** main  
**Active hardening branch:** r2-1.6.0-security  
**Roadmap status reviewed:** 2026-11-08  
**Latest branch commit:** `30e657bea4c419bf0d8d6f2900a5f4d1eb257df9` (R3 security design baseline; CI pending).  
**Latest completed CI:** [run 42518629698](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42518629698) — all five jobs passed on commit `268cdeee3909be07bcaba3209a57f4ca52be59ac`: Python 3.10/3.11/3.12, Docker API build/container smoke, and containment integration (nftables + iptables in disposable network namespaces).  
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
- R2-R5 remain open. The product is not production-ready; dashboard/service authentication, containment, queue reliability, audit/reporting and supervised pilot acceptance still need completion.

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

### R3 — Complete operator and service security (IN PROGRESS)

**Latest completed code CI:** [run 42517900655](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42517900655) — 62 tests passed on Python 3.10/3.11/3.12; Docker API smoke and both containment integration jobs passed. The latest completed full workflow on the branch is [run 42518629698](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42518629698), passing all five jobs on `268cdeee3909be07bcaba3209a57f4ca52be59ac`.

Implemented and covered so far:
- Dashboard passwords are stored as salted PBKDF2-HMAC-SHA256 hashes; production rejects legacy plaintext credentials.
- Persistent SQLite sessions store only token hashes and support expiry and revocation.
- Login CSRF token, state-changing POST logout, CSRF header validation, and login throttling across IP and account scopes.
- Dashboard route role checks and tenant context propagation to gateway requests.
- Secure/HttpOnly/SameSite cookies when production cookie mode is enabled; response security headers and no-store policy.
- Decision-service rejects missing/incorrect internal service keys on /v1 routes and fails closed in production when the key is unset.
- Gateway patch adds the internal decision-service credential to decision/execute requests and replaces wildcard credentialed CORS with configured explicit origins.
- Compose keeps decision service on the private Docker network, binds API/dashboard host ports to localhost, and requires deployment secrets. A safe .env.example and deployment guidance are committed.
- R3 tests now cover login/session/CSRF/role flows, service-key rejection, fail-closed configuration, CORS patch behaviour and source-drift failures.

Operator identity and service authorization design baseline: [docs/R3_OPERATOR_IDENTITY_AND_SERVICE_AUTH.md](R3_OPERATOR_IDENTITY_AND_SERVICE_AUTH.md). This is a specification only; implementation and acceptance tests are not yet complete.

Still required before R3 can be marked complete:
1. Implement signed operator identity assertions and bind verified identity to gateway audit events for dashboard actions. The dashboard currently authenticates the operator locally but sends a shared gateway API key; audit records must preserve the authenticated username, role, tenant, action, approval and command correlation without trusting client-supplied actor headers.
2. Enforce least privilege end-to-end. Define service identities/scopes for dashboard, NAD processor, API gateway and decision service; avoid giving dashboard a general admin API key. Add negative tests proving each service cannot call unrelated admin/agent endpoints.
3. Audit every dashboard route and frontend action: ensure every state-changing operation requires CSRF and correct role, and every API proxy call carries the authenticated tenant. Add cross-tenant isolation tests, including object-ID substitution and audit/report endpoints.
4. Review login throttling against reverse-proxy deployments. Trust forwarded client IP only from configured trusted proxies; add a global/account-only throttle resilient to rotating source IPs and a bounded cleanup/retention strategy for the attempts table.
5. Harden browser policy: remove inline event handlers/scripts/styles where practical and remove `unsafe-inline` from CSP; test cookie Secure behaviour behind the documented TLS reverse proxy and confirm HSTS is only emitted for HTTPS deployments.
6. Add production startup validation for missing/weak credentials, placeholder values, invalid CORS origins, insecure cookie settings, shared/default secrets and writable persistent storage. Do not silently fall back to development credentials in production.
7. Add a full Compose integration test: fresh environment, all services healthy, dashboard login, invalid/expired/revoked session, CSRF denial, tenant-scoped API request, decision-service auth, and service-to-service failure when the secret is wrong.
8. Confirm documentation accurately describes credential migration, secret generation, reverse-proxy/TLS requirements, backup/restore of the session DB and operator onboarding. Never commit real .env or credentials.

Do not call R3 complete based on the current passing CI alone. The current evidence proves the listed automated tests and Docker API smoke, not full dashboard + decision-service deployment acceptance.

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

## Immediate work order

R0, R1 and R2 code gates are complete on the security branch. R3 is underway: its first dashboard/service-auth controls and 62-test CI baseline are on the branch, but operator attribution, service least privilege, proxy-aware throttling, CSP hardening and full Compose acceptance remain. Continue R3 before starting R4. Keep the security branch isolated from `main`.

## GitHub delivery rules

- Every logical change must be committed and pushed to r2-1.6.0-security (or a focused child branch) with a meaningful commit message.
- Update this roadmap and the changelog when phase status changes.
- Attach test evidence to the commit/PR and identify the exact SHA tested.
- Do not force-push, do not commit secrets, and do not merge failed or unverified builds.
- Keep main stable; merge only through a reviewed PR after required CI checks pass.
