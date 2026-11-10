# CyberGuardian — hardened deployment defaults

Authorized defensive use only. CyberGuardian is a supervised control plane, not a replacement for a SOC, backups, patching, or identity governance.

## Network posture

| Setting | Production default | Purpose |
|---|---|---|
| Dashboard | `127.0.0.1:3000` | Not published to public interfaces |
| API gateway | `127.0.0.1:8080` | Local operator access / reverse-proxy upstream |
| Decision service | Internal Compose network only | No host-published port |
| CORS | Explicit `CG_ALLOWED_ORIGINS` | No wildcard origins with credentials |
| Decision-service API | `X-Decision-Service-Key` required | Authenticates gateway-to-decision traffic |
| Client Mode | ON | Isolate / kill / block require human approval |
| Agent identity | Required in production | Per-agent credentials and tenant/asset binding |
| Dashboard cookie | Secure, HttpOnly, SameSite=Lax | Requires HTTPS or a browser-trusted localhost origin |

The Compose file binds dashboard and API ports to loopback and keeps the decision service private. Standalone `start.sh` also forces loopback binding whenever production identity enforcement is enabled and rejects an explicit non-loopback bind. The NAD synthetic `/v1/simulate` endpoint is disabled in production. For remote operator access, use an SSH tunnel or a TLS reverse proxy. Do not publish ports 3000, 8080, or 8001 directly to the internet.

## Required deployment configuration

Create a private `.env` file beside the Compose deployment file. Generate the decision-service secret with a cryptographically secure generator, for example:

```bash
openssl rand -hex 32
```

Run `./scripts/setup_credentials.sh` to create the administrator credential and four distinct service/signing secrets. Copy the generated service values into the private Compose `.env` file. Set:

- `CYBERGUARDIAN_API_KEY`: must match the administrator API key stored in `data/credentials.json`.
- `CG_DASHBOARD_API_KEY`: dedicated dashboard-to-gateway identity; at least 32 bytes.
- `CG_NAD_API_KEY`: dedicated NAD-to-gateway identity; at least 32 bytes and scoped to detection submission only.
- `CG_OPERATOR_ASSERTION_SECRET`: dedicated HMAC secret used to bind dashboard requests to the authenticated operator, tenant, method and path; at least 32 bytes.
- `DECISION_SERVICE_API_KEY`: dedicated gateway-to-decision-service identity; at least 32 bytes.
- `CG_PRODUCTION=1`
- `CG_REQUIRE_AGENT_IDENTITY=1`
- `CG_COOKIE_SECURE=1`
- `CG_ALLOWED_ORIGINS`: comma-separated exact browser origins, for example `https://guardian.example.com`. Never use `*`.
- `CG_DATA_HOST_DIR`: persistent host directory for credentials, database, and dashboard sessions.

All five administrator/service/signing values must be at least 32 bytes and pairwise unique. Never reuse the administrator key as a dashboard, NAD, decision-service or operator-signing secret. Standalone `./start.sh` reads the generated service secrets from `data/credentials.json`; production startup fails before launching services if they are absent, too short or duplicated.

Keep `.env`, `data/credentials.json`, and the dashboard SQLite database out of Git. Restrict the data directory to the service operator (directory mode 700; credential and database files mode 600). If the bootstrap admin or lab-agent key has been exposed, rerun setup with a blank admin-key prompt and `CG_ROTATE_BOOTSTRAP_AGENT_KEY=1` to generate fresh bootstrap credentials; this does not rotate enrolled per-device credentials.

## Audit checkpoint and recovery

Credential setup provisions a separate 256-bit HMAC checkpoint key as `audit_checkpoint_key_hex`. The audit export, verify and restore commands read it from `data/credentials.json` (or the configured `CG_DATA_DIR`) unless `CG_AUDIT_CHECKPOINT_KEY_HEX` is explicitly supplied. Copy the key into an independent secrets manager or offline recovery store; the controller's local credential file must not be its only copy.

Create a verified signed checkpoint on an independently mounted destination:

```bash
python3 scripts/export_audit_ledger.py --out /secure/offhost/cyberguardian-audit.jsonl
```

Verify the manifest and snapshot before relying on them:

```bash
python3 scripts/verify_audit_checkpoint.py --snapshot /secure/offhost/cyberguardian-audit.jsonl
```

Perform a recovery drill on a clean, isolated controller using the independently stored checkpoint key:

```bash
CG_AUDIT_CHECKPOINT_KEY_HEX="<original-checkpoint-key>" python3 scripts/restore_audit_checkpoint.py --snapshot /secure/offhost/cyberguardian-audit.jsonl --destination /var/lib/cyberguardian/audit_ledger.jsonl
```

Record the source commit, checkpoint timestamp, verification output, restore output and independent storage location in the pilot evidence pack. A local checkpoint alone is not an off-host backup or a completed restore drill.

## Dashboard authentication

Run `./scripts/setup_credentials.sh` before production startup. It writes the administrator password as a salted PBKDF2-HMAC-SHA256 hash and atomically replaces the credentials file; it no longer stores plaintext passwords.

The dashboard uses:
- Persistent SQLite sessions with hashed random session tokens, expiry, and revocation.
- Hashed CSRF tokens and a CSRF header on state-changing operator requests.
- A double-submit token on the login form.
- Persistent login throttling by client address and username.
- Role checks (`admin`, `operator`, `analyst`, `viewer`) and tenant identity carried into gateway requests.
- Secure/HttpOnly session and CSRF cookies in production.
- No-store responses and browser security headers.

Existing plaintext `admin_password` credentials are accepted for migration only when `CG_PRODUCTION` is off. Production mode refuses plaintext password records. Re-run the credential setup script to generate a password hash before enabling production mode.

The dashboard authentication database is stored under `CG_DATA_DIR`; mount that directory persistently so sessions and login throttling survive container recreation.

## Service authentication and CORS

Every decision-service `/v1/*` route requires `X-Decision-Service-Key`; in production, a missing key returns 503 and an invalid key returns 401. The gateway's deterministic assembler patch adds the same header to its decision, execute, and action-dispatch requests. The dashboard service key is limited to the documented dashboard routes and requires a request-bound operator assertion in production. The NAD service key is limited to `POST /v1/detections`. Unknown service identities and out-of-scope methods/routes are denied.

The API gateway CORS policy is generated from `CG_ALLOWED_ORIGINS`. The assembler rejects an empty origin list or wildcard origin. If the operator dashboard is hosted behind a reverse proxy, configure the exact HTTPS origin and ensure the proxy terminates TLS.

## Before any client network

1. Run the automated test suite and the disposable network-namespace containment integration job.
2. Confirm Client Mode is ON in the dashboard.
3. Confirm the decision-service secret is set identically for the API and decision service.
4. Confirm the API admin key matches the key in `data/credentials.json`.
5. Confirm per-agent enrollment, tenant binding, and key rotation.
6. Validate the actual Android/Termux-Ubuntu kernel, firewall backend, and pidfd availability during the supervised pilot.
7. Do not run destructive containment tests on a client or production host.

## Operator access

Local dashboard:

```text
http://127.0.0.1:3000
```

For remote access, prefer an SSH tunnel to the controller:

```bash
ssh -L 3000:127.0.0.1:3000 user@controller
```

If using a reverse proxy, terminate TLS there and set `CG_ALLOWED_ORIGINS` to the exact HTTPS origin. Do not disable Secure cookies to work around an incorrectly configured proxy.
