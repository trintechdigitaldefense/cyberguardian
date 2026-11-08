# CyberGuardian R2 push and verification status

**Branch:** `r2-1.6.0-security`  
**R0 validated code commit:** `3a2f9a393f4e86789823035bbaab0cec430449ca`  
**CI evidence:** [run 42510671312](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42510671312)  
**Status:** R0 passed; R1 is next.

## GitHub delivery inventory

The following are tracked on this branch:

- Linux agent, containment engine, offline queue and command crypto module
- API agent identity module and gateway source/assembler
- Decision service and dashboard
- Startup, status and stop scripts
- Credential setup script
- CI workflow and regression tests

Presence on GitHub is not equivalent to security acceptance. The R1-R4 items remain open as described in `docs/ROADMAP.md`.

## R0 evidence

- Canonical gateway source: `control-plane/api/gateway_z/00.txt` through `05.txt`.
- Restored R2's corrupted `05.txt` from the verified `main` version.
- Assembled gateway: 53,731 bytes.
- SHA-256: `39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674`.
- Assembler verifies all six chunk names, strict base64 decoding, zlib decompression, UTF-8, gateway marker, Python AST, SHA-256 and expected byte size; it writes output atomically.
- Runtime data/config paths are portable between repository and container layouts.
- Docker working directory preserves the repository-relative paths expected by the gateway.

## CI results — run 42510671312

- Python 3.10: passed
- Python 3.11: passed
- Python 3.12: passed
- Automated tests: 4 passed in 0.08 seconds (Python 3.12 log)
- Application compile checks: passed
- Docker image build: passed
- Container `/health` smoke test: passed

This is a successful R0 CI gate. It is not a full integration test, security assessment, or ten-minute soak test.

## Current test inventory

- `tests/test_command_crypto.py`
- `tests/test_gateway_assembly.py`

Four test functions currently pass. Expand the suite with R1-R4 acceptance tests; do not overstate coverage.

## Next: R1

1. Call `verify_command` on every received command before invoking containment.
2. Reject unsigned commands in production, and require valid expiry, asset/tenant binding, approval reference and nonce.
3. Add durable replay protection.
4. Use unique per-agent credentials with enrollment, rotation and revocation.
5. Add negative tests for missing/bad signatures, expiry, replay, wrong tenant, wrong asset and altered parameters.

Do not merge to `main` until R1-R5 and release acceptance are complete.
