# CyberGuardian 1.6.0-r2 — Security and reliability hardening

**Working branch:** `r2-1.6.0-security`  
**Status:** Engineering / validation in progress. Not a production release.

## Verified GitHub changes

- API gateway bootstrap and Docker image build invoke the gateway assembler.
- Canonical gateway source is the six-part `control-plane/api/gateway_z/00.txt`–`05.txt` set.
- The R2 final fragment was restored to the version on `main` after CI proved the R2 copy produced a truncated zlib stream.
- Gateway assembly now validates the chunk set, strict base64 decoding, decompression, UTF-8, source marker, Python syntax, SHA-256 and expected byte size; output is written atomically.
- CI installs declared dependencies without suppressing installation errors and runs gateway assembly, automated tests, compile checks and a Docker health smoke.
- Regression coverage now includes gateway assembly/digest validation and command-crypto unit tests.

## Not yet accepted / still requires implementation or evidence

- Signed command verification is not wired into the agent's command execution path. The agent currently imports and calls the containment executor without first calling `verify_command`.
- Agent identity enforcement remains permissive in non-strict mode and needs per-agent enrollment, tenant/asset binding, replay protection, rotation and revocation.
- Containment safety must be reviewed against the full acceptance criteria and tested in disposable VMs/mocks.
- Dashboard still has in-memory sessions and plaintext password fallback/storage in the reviewed branch; PBKDF2/session-hardening claims must not be treated as delivered.
- Decision-service authentication, tenant authorization and durable history need end-to-end verification.
- Offline queue still needs loss, concurrency, overflow, acknowledgement and reconnect tests.
- CORS, service networking, secrets handling, audit durability, fleet lifecycle and reporting integration remain open.
- The test suite is small and does not yet cover full platform integration or production deployment.
- The existing `docs/TEN_MINUTE_TEST_REPORT.md` records approximately 7 seconds of active checks. It is not a 600-second soak test.

## Gateway integrity

Expected SHA-256: `39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674`  
Expected size: `53731` bytes

## Release decision

**Not production-ready.** Do not merge to `main` or deploy to a client network until R0-R5 acceptance criteria in `docs/ROADMAP.md` are evidenced on the exact release commit. Human approval remains required for disruptive response actions.
