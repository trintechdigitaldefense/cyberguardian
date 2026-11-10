# CyberGuardian R2 push and verification status

**Branch:** `r2-1.6.0-security`  
**R0 code commit:** `3a2f9a393f4e86789823035bbaab0cec430449ca`  
**R1 code commit:** `786b6283562ddd98b601142e33c4624a13a85b50`  
**Latest verified CI:** [run 42511953408](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42511953408)  
**Status:** R0 and R1 code/CI gates passed; R2 is next.

## R0 — Gateway and Docker

- Canonical source: `control-plane/api/gateway_z/00.txt`–`05.txt`.
- Original source SHA-256: `39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674`.
- Deterministic gateway patch fixes command-poll SQLite audit transaction ordering.
- Final assembled gateway: 54,118 bytes.
- Final SHA-256: `6d6a7bac74729a5e2bc8b8dc39c5a73f8c98611f8b2cdc32b12acc6ea00f2c20`.
- Docker build and container `/health` smoke passed.

## R1 — Signed commands and agent identity

- Agent verifies command HMAC before execution; signature binds command ID, tenant, asset, action, target, full parameters, expiry, approval reference and nonce.
- Durable SQLite replay ledger prevents re-use of command IDs/nonces.
- Controller signs command responses using the enrolled agent's dedicated command secret.
- Per-agent API key and identity-secret enrollment, rotation and revocation are implemented.
- API middleware binds agent credentials to one asset and tenant and limits keys to agent endpoints.
- Registration and heartbeat use signed per-agent identity.
- Command-poll audit writes occur after the command transaction commits.

### Latest CI run 42511953408

- Python 3.10: passed
- Python 3.11: passed
- Python 3.12: passed
- Automated tests: 12 passed
- Compile checks: passed
- Docker image build: passed
- Container `/health`: passed

## Current test inventory

- `tests/test_command_crypto.py`
- `tests/test_agent_security.py`
- `tests/test_agent_api_integration.py`
- `tests/test_agent_enrollment.py`
- `tests/test_gateway_assembly.py`

These are focused regression and integration tests, not a full platform security assessment.

## Next: R2 — Containment and rollback

1. Verify PID plus process-start-time identity before any process action.
2. Reject process-hint mismatches and validate targets with strict parsers.
3. Use CyberGuardian-owned firewall chains only; never flush unrelated host rules.
4. Validate IPv4 and IPv6 paths and controller recovery exceptions.
5. Make restore verify the actual firewall state before reporting success.
6. Test destructive paths only in disposable VMs/mocks.
7. Add failure-injection and rollback integration tests.

Do not merge to `main` or deploy to a client network until R2-R5 acceptance and pilot gates pass.
