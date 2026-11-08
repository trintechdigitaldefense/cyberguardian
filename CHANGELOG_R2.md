# CyberGuardian 1.6.0-r2 — Security and reliability hardening

**Working branch:** `r2-1.6.0-security`  
**Status:** R0 build/deployment gate passed; R1-R5 remain in progress. Not a production release.

## R0 — Completed and verified

Code commit: `3a2f9a393f4e86789823035bbaab0cec430449ca`  
CI evidence: [GitHub Actions run 42510671312](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42510671312)

- Restored the corrupted final `gateway_z/05.txt` fragment from the verified `main` branch source.
- Made the six-part `gateway_z/00.txt`–`05.txt` set canonical for gateway assembly.
- Added strict fragment, base64, zlib, UTF-8, AST, SHA-256 and expected-size checks; generated output is written atomically.
- Added portable runtime data/config paths and corrected the Docker working directory to preserve expected repository-relative paths.
- Changed CI to fail closed on dependency installation and to run assembly, pytest, compile checks, Docker build and container health smoke.
- Python 3.10, 3.11 and 3.12 passed; all four current automated tests passed; Docker image built; container `/health` returned HTTP 200.

Gateway SHA-256: `39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674`  
Gateway size: `53731` bytes.

## R1-R4 — Open engineering work

- Signed command verification is not yet wired into the agent's command execution path. The agent must reject invalid, expired, replayed, wrong-tenant and wrong-asset commands before any action.
- Agent identity still needs strict production enrollment, per-agent credentials, tenant/asset binding, replay protection, rotation and revocation.
- Containment safety needs review and isolated-VM/mock acceptance tests.
- Dashboard still has in-memory sessions and plaintext password fallback/storage in the reviewed branch; password/session hardening is not delivered.
- Decision-service authentication, tenant authorization and durable history need verification.
- Offline queue needs loss, concurrency, overflow, acknowledgement and reconnect tests.
- CORS, service networking, secrets handling, audit durability, fleet lifecycle and reporting integration remain open.

## R5 — Pilot acceptance

The existing `docs/TEN_MINUTE_TEST_REPORT.md` records approximately 7 seconds of active checks. It is not a 600-second soak test. R5 requires a genuine 600-second run against an identified commit, complete logs/results, and a supervised end-to-end client-pilot workflow.

## Release decision

**Not production-ready.** Do not merge to `main` or deploy to a client network until R1-R5 acceptance criteria in `docs/ROADMAP.md` are evidenced on the exact release commit. Human approval remains required for disruptive response actions.
