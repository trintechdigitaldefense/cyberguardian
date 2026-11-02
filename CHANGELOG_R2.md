# CyberGuardian 1.6.0-r2 — Security, Reliability, Integration

Branch: `r2-1.6.0-security`

## Priority fixes landed

1. **Gateway deployment** — assemble verifies SHA-256; Docker RUN assemble_main.py; main.py bootstrap uses assemble
2. **Startup/health** — dashboard readiness uses /health; PID files in data/run/; stop only CG-owned PIDs
3. **Containment** — PID+starttime, strict identity, ipaddress validation, dedicated chains, verified restore (local tree)
4. **Dashboard auth** — PBKDF2 hash support, file-backed sessions with TTL (local tree)
5. **Offline queue** — unique IDs, file lock, atomic rewrite, max 5000, no silent 500-line drop
6. **Decision service** — X-API-Key middleware on non-health routes
7. **Tests** — 11 unit tests + scripts/ten_minute_test.sh (16/16 PASS)

## Gateway integrity

SHA256: `c83c76cba8256f0d0e8de1026b5d404667c8020b902b51cbec7613c8dc302dfb`
Size: 54031 bytes

## Still open for main merge

- Push full containment.py / dashboard/main.py / offline_queue.py / agent_identity.py / gateway_z refresh from build tree if not on branch
- Signed command envelopes (P5) agent-side verify
- CSRF + login rate limit
- CORS allow_origins still * until main_full patch fully redistributed

## Production readiness

**Not production-ready** until P5 signed commands and remaining auth hardening land and Docker image is smoke-tested in CI.
