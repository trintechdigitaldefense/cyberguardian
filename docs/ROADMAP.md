# CyberGuardian Roadmap — 1.6.0 Security Release

**Repository:** https://github.com/trintechdigitaldefense/cyberguardian  
**Primary branch:** main  
**Active hardening branch:** r2-1.6.0-security  
**Roadmap status reviewed:** 2026-11-08  
**Current hardening branch head at review:** 3a2f9a393f4e86789823035bbaab0cec430449ca

This roadmap preserves the original eight product phases and adds a release-readiness gate. A phase is not complete merely because a module or documentation entry exists: completion requires code on GitHub, tests passing against the same commit, and evidence for the phase acceptance criteria.

## Executive status

- main is at cf4832d1e36dd8139aaac3df7750386c482ff34b.
- r2-1.6.0-security is 29 commits ahead of main, with no commits behind it.
- R2 contains gateway assembly/checksum logic, a Docker assembly step, command-signature code, and a small unit-test addition.
- Do not merge R2 into main yet. R0 has passed on code commit `3a2f9a3`: Python 3.10/3.11/3.12, gateway assembly, four automated tests, compilation, Docker build, and container `/health` smoke all passed in Actions run [42510671312](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42510671312).
- Core agent, containment, offline queue, identity, decision-service, dashboard, and startup/status/stop files are now confirmed tracked on the R2 GitHub branch. Their presence does not mean their security acceptance tests are complete.
- docs/TEN_MINUTE_TEST_REPORT.md records 16 checks passing in 7 seconds, not a ten-minute/600-second test. This is a short smoke-check report, not a completed ten-minute soak test.
- R2's changelog says the product is not production-ready until signed-command verification, remaining authentication hardening, and Docker smoke testing are complete.

## Original eight phases

| Phase | Product area | Current assessment | Exit criteria |
|---|---|---|---|
| 1 | API Gateway | Implemented foundation; release-blocking packaging/integrity/CI issues remain on R2 | Clean clone assembles gateway deterministically; checksum and source completeness verified; API imports and /health returns 200; Docker build and container smoke pass |
| 2 | Decision Engine | Existing risk scoring/playbook decision service; service authentication and durable decision history need verification | Authenticated service-to-service calls; tenant-scoped decisions; documented scoring/playbook tests; durable decision and action history |
| 3 | Linux Agent | Agent and polling flow exist; signed-command enforcement must be proven end-to-end | Per-agent identity; signed, expiring, single-use commands; replay and wrong-asset rejection; safe heartbeat/enrollment; reconnect tests |
| 4 | Containment Engine | Containment implementation exists, but complete hardened implementation is not confirmed on remote branch | PID plus process-start-time validation; strict target checks; dedicated firewall chains; safe IPv4/IPv6 validation; controller recovery path; verified rollback; isolated-VM and mocked tests |
| 5 | Dashboard | Operator dashboard exists; authentication hardening remains incomplete | Strong password hashing; persistent expiring/revocable sessions; Secure/HttpOnly/SameSite cookies; CSRF protection; login throttling; operator attribution; role checks |
| 6 | Fleet Management | Basic registration, inventory, and last-seen functionality exist | Tenant-safe enrollment and inventory; unique device identity; stale/offline states; lifecycle/revocation; bounded discovery; multi-agent integration tests |
| 7 | Audit & Compliance | Audit trail and action history exist | Durable append-only or tamper-evident audit; actor/tenant/asset/approval/command correlation; retention/export; denied and failed action records; integrity tests |
| 8 | Reporting | Weekly digest/scorecard foundations exist | Reproducible report generation; verified data provenance; PDF/CSV export tests; time-zone and date-window correctness; report access controls |

## Release-readiness phase (required before a client pilot)

This is a cross-cutting gate, not a replacement for the eight product phases.

### R0 — Recover and stabilise the R2 branch (<escape>COMPLETED</escape>)

1. Reproduce the latest R2 CI failure locally and in GitHub Actions.
2. Fix gateway packaging so committed source fragments, assembler, and expected SHA-256 all refer to the same exact gateway artifact. Remove stale or competing chunk formats from the active build path.
3. Ensure all required gateway chunks are tracked on the branch. The current PUSH_STATUS.md lists only a partial gateway_hex set and says other required files remain in local build trees.
4. Push the complete, reviewed implementations of containment, dashboard, offline queue, identity, decision service, startup/status/stop scripts, and tests. Never claim a local-only file has been delivered.
5. Make CI fail closed: no ignored dependency-install failures, no skipped tests presented as success, and run assembly, pytest, compile, Docker build, and container health smoke.
6. Re-run CI on the resulting commit and record the exact commit SHA and all job outcomes.

R0 is complete only when the exact branch head has green required checks, gateway assembly is reproducible from a fresh clone, and the Docker container reaches healthy status.

### R1 — Complete command and identity security

- Require signed command envelopes in production; no unsigned fallback when CG_PRODUCTION=1.
- Bind signature to command ID, tenant, asset, action, parameters, approval reference, nonce, and expiry.
- Persist replay protection and reject expired, duplicated, altered, wrong-tenant, and wrong-asset commands.
- Use dedicated per-agent credentials; prohibit admin credentials on endpoints.
- Add key rotation and revocation tests.

### R2 — Complete containment and recovery safety

- Test only in disposable VMs or mocks; never use production hosts for destructive tests.
- Verify PID reuse protection, process-hint mismatch rejection, IP parsing, controller allowlisting, dedicated firewall rules, IPv4/IPv6 behaviour, and exact rollback.
- Verify rollback only reports success after firewall state is restored and checked.

### R3 — Complete operator and service security

- Add CSRF protection, login throttling, session revocation, secure cookie settings, role/tenant authorization, and operator attribution.
- Replace wildcard credentialed CORS with explicit trusted origins.
- Authenticate decision-service routes and restrict backend service exposure to private networks.
- Use separate least-privilege service credentials and managed secrets; never commit credentials.

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

The next engineering task is R1: wire signed command verification into the agent before execution, make production verification fail closed, and complete per-agent identity, tenant/asset binding, expiry, replay protection, rotation and revocation tests. Keep R2 isolated from `main`; proceed through R1–R5 in order.

## GitHub delivery rules

- Every logical change must be committed and pushed to r2-1.6.0-security (or a focused child branch) with a meaningful commit message.
- Update this roadmap and the changelog when phase status changes.
- Attach test evidence to the commit/PR and identify the exact SHA tested.
- Do not force-push, do not commit secrets, and do not merge failed or unverified builds.
- Keep main stable; merge only through a reviewed PR after required CI checks pass.
