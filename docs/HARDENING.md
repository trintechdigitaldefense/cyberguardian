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

The Compose file binds dashboard and API ports to loopback and keeps the decision service private. For remote operator access, use an SSH tunnel or a TLS reverse proxy. Do not publish ports 3000, 8080, or 8001 directly to the internet.

## Required deployment configuration

Create a private `.env` file beside the Compose deployment file. Generate the decision-service secret with a cryptographically secure generator, for example:

```bash
openssl rand -hex 32
```

Set these values:

- `CYBERGUARDIAN_API_KEY`: must match the admin API key stored by `scripts/setup_credentials.sh`.
- `DECISION_SERVICE_API_KEY`: at least 32 random characters; Compose passes the same value to the API gateway and decision service.
- `CG_PRODUCTION=1`
- `CG_REQUIRE_AGENT_IDENTITY=1`
- `CG_COOKIE_SECURE=1`
- `CG_ALLOWED_ORIGINS`: comma-separated exact browser origins, for example `https://guardian.example.com`. Never use `*`.
- `CG_DATA_HOST_DIR`: persistent host directory for credentials, database, and dashboard sessions.

Keep `.env`, `data/credentials.json`, and the dashboard SQLite database out of Git. Restrict the data directory to the service operator (directory mode 700; credential and database files mode 600).

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

Every decision-service `/v1/*` route requires `X-Decision-Service-Key` when a key is configured. In production, a missing key returns 503 and an invalid key returns 401. The gateway's deterministic assembler patch adds the same header to its decision, execute, and action-dispatch requests.

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
