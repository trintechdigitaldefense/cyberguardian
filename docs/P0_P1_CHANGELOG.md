# P0 + P1 changes

## P0

### start.sh / status.sh
- Real HTTP readiness waits for decision, API, dashboard
- Assemble failure aborts start
- Partial start rolls back uvicorn/agent
- `status.sh` reports healthy / degraded / unhealthy / stopped

### containment.py
- PID + `/proc` starttime identity (PID reuse protection)
- Strict cmdline/exe hint match when required
- IP validation via `ipaddress` (reject loopback/multicast/unspecified)
- Dedicated `inet cyberguardian` nft table / `CG_BLOCK`+`CG_ISOLATE` iptables chains
- Controller hostname → IP resolution (v4/v6)
- Restore only removes CG objects; marker cleared only after verify

### Gateway approval authority
- Single-use pending→approved CAS update
- Commands carry `_expires_at` (15m), `_single_use`, `_approval_id`
- Agent pull skips expired; CAS queued→delivered
- Decision-service `auto_approved` does not authorize host commands; gate is authority

### Agent identity
- `CG_REQUIRE_AGENT_IDENTITY` / `CG_PRODUCTION` / credentials `require_agent_identity` → fail closed
- Admin API key rejected on agent register/commands paths
- Fingerprint change refused in production

## P1 (started)
- Dashboard sessions in `data/dashboard_sessions.json` with TTL
- Secure cookie flag via `CG_SECURE_COOKIE=1`
- PBKDF2 password hash support (`admin_password_hash` + salt)
- setup_credentials writes hash

## Still operator action
- Push full `gw_src_*.txt` / `main_full.py` so clean clones assemble the gateway
