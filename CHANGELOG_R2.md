# CyberGuardian 1.6.0-r2 — Security and reliability hardening

**Working branch:** `r2-1.6.0-security`  
**Status:** R0 and R1 code/CI gates passed. R2-R5 remain open. Not a production release.

## R0 — Gateway and Docker: complete

Code commit: `3a2f9a393f4e86789823035bbaab0cec430449ca`

- Restored the final gateway fragment and made the six-part gateway_z source canonical.
- Added strict fragment, base64, zlib, UTF-8, AST, source hash and final output hash/size validation.
- Added portable runtime paths and corrected Docker working directory.
- CI verifies gateway assembly, tests, compile, Docker build and health.

## R1 — Signed commands and agent identity: complete

Code commit: `786b6283562ddd98b601142e33c4624a13a85b50`  
CI evidence: [run 42511953408](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42511953408)

- Added controller-side HMAC signing with a dedicated command secret per enrolled agent.
- Added agent-side signature, expiry, nonce, approval-reference, asset and tenant verification before command execution.
- Added persistent SQLite replay protection for command IDs and nonces.
- Added per-agent API key and identity-secret enrollment, rotation and revocation.
- Restricted agent keys to their own asset/tenant and agent-specific endpoints.
- Added signed registration and heartbeat plus command-result reporting checks.
- Fixed nested SQLite audit writes in command polling.
- Added regression/integration tests for signing, replay, enrollment, rotation, revocation, tenant isolation and command delivery.

CI passed on Python 3.10, 3.11 and 3.12; 12 tests passed; Docker image build and container health smoke passed.

## R2-R4 — Open engineering work

- Containment PID identity, firewall isolation and verified rollback require isolated-VM/mock tests.
- Dashboard still has in-memory sessions and plaintext password fallback/storage in the reviewed branch; password/session hardening is not delivered.
- Decision-service authentication, tenant authorization and durable history need verification.
- Offline queue needs loss, concurrency, overflow, acknowledgement and reconnect tests.
- CORS, service networking, secrets handling, audit durability, fleet lifecycle and reporting integration remain open.

## R5 — Pilot acceptance

The existing `docs/TEN_MINUTE_TEST_REPORT.md` records approximately 7 seconds of active checks. It is not a 600-second soak test. R5 requires a genuine 600-second run against an identified commit, complete logs/results, and a supervised end-to-end client-pilot workflow.

## Release decision

**Not production-ready.** Do not merge to `main` or deploy to a client network until R2-R5 acceptance criteria in `docs/ROADMAP.md` are evidenced on the exact release commit. Human approval remains required for disruptive response actions.
