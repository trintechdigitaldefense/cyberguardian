# CyberGuardian Roadmap — 1.6.0 Security Release

**Repository:** https://github.com/trintechdigitaldefense/cyberguardian  
**Primary branch:** main  
**Active hardening branch:** r2-1.6.0-security  
**Roadmap status reviewed:** 2026-11-08  
**Current hardening branch head at review:** d1ec90dd5840a3f310f01cae1d0080c9c9a1940d

This roadmap preserves the original eight product phases and adds a release-readiness gate. A phase is not complete merely because a module or documentation entry exists: completion requires code on GitHub, tests passing against the same commit, and evidence for the phase acceptance criteria.

## Executive status

- main is at cf4832d1e36dd8139aaac3df7750386c482ff34b.
- r2-1.6.0-security is 64 commits ahead of main, with no commits behind it.
- R2 now includes process identity evidence propagation, PID/start-time validation, pidfd-bound signalling where supported, strict IP parsing, controller recovery allowlisting, dual-stack firewall handling, verified nftables rule activation, corrupt-marker fail-closed recovery, and human approval for disruptive playbook actions. A final exact-token nft rule-verification change is on the branch and awaiting its own CI run.
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
| 4 | Containment Engine | Containment implementation exists, but complete hardened implementation is not confirmed on remote branch | PID plus process-start-time validation; strict target checks; dedicated firewall chains; safe IPv4/IPv6 validation; controller recovery path; verified rollback; isolated-VM and mocked tests |
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

### R2 — Complete containment and recovery safety (IN PROGRESS)

**Latest verified test baseline:** commit `70368f0dd173eabda32323adf493145c6c5ddd47`; Actions run [42515663633](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42515663633). Python 3.10/3.11/3.12 and Docker API smoke passed; 35 automated tests passed. The branch has since received an additional exact-token nft rule-verification fix and regression test; CI for the newer head must pass before this section is advanced.

Implemented and covered by automated tests:
- Process actions require command-line or start-time evidence; PID start-time mismatch, hint mismatch and unreadable proc identity fail closed.
- Agent inventory captures process start time and the decision service passes that identity evidence to the kill action.
- pidfd-bound signalling is used where supported; tests exercise the pidfd path.
- IP parsing rejects invalid, loopback, unspecified, multicast and link-local targets.
- Isolation refuses to proceed without a resolvable controller recovery address.
- nftables and iptables fallback paths include controller recovery allowlisting and dual-stack handling; isolation does not grant general DNS or established-session egress.
- Firewall rules are checked after insertion; rollback retains markers if the recorded backend is unavailable or state markers are corrupt.
- Disruptive playbook actions (kill, isolate, block) remain human-approved. An arbitrary `allowlist_id` string is not accepted as authorization; a real tenant-scoped policy/approval service is required before any automatic disruptive allowlisting is introduced.

Still required before R2 can be marked complete:
- Run privileged integration tests in disposable Linux VMs for nftables and iptables/ip6tables; verify actual rule ordering, controller connectivity, IPv4 and IPv6 traffic, and restoration after normal and interrupted runs.
- Verify rollback leaves unrelated host firewall rules untouched, including pre-existing tables/chains and duplicate jumps.
- Exercise process termination against a controlled child process on supported kernels and document the minimum kernel/pidfd requirement; test unsupported-kernel fallback behaviour.
- Add failure-injection coverage for partial rule application and marker-write failure; verify the host never reports success while isolation/rollback state is uncertain.
- Re-run the full matrix against the latest branch head and attach the exact commit SHA and artifacts.
- Never run destructive containment tests on a client or production host.

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

The next engineering task is R2: complete containment and rollback safety validation. Keep the security branch isolated from `main`; proceed through R2–R5 in order.

## GitHub delivery rules

- Every logical change must be committed and pushed to r2-1.6.0-security (or a focused child branch) with a meaningful commit message.
- Update this roadmap and the changelog when phase status changes.
- Attach test evidence to the commit/PR and identify the exact SHA tested.
- Do not force-push, do not commit secrets, and do not merge failed or unverified builds.
- Keep main stable; merge only through a reviewed PR after required CI checks pass.
