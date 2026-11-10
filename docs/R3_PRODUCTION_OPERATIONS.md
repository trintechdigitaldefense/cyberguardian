# CyberGuardian R3 production operations

This guide covers the production configuration required by the R3 security controls. Keep the deployment secrets outside Git and protect the persistent data directory.

## 1. Generate independent secrets

Generate a different value for every variable below. Do not reuse one secret across services.

```bash
openssl rand -hex 32
```

| Variable | Must be available to | Purpose |
|---|---|---|
| `CYBERGUARDIAN_API_KEY` | API gateway only | Human/admin API credential; must match `api_key` in `credentials.json` |
| `CG_DASHBOARD_API_KEY` | Dashboard and API gateway | Dashboard workload identity; route-limited |
| `CG_NAD_API_KEY` | NAD processor and API gateway | Detection-submission identity; POST `/v1/detections` only |
| `CG_OPERATOR_ASSERTION_SECRET` | Dashboard and API gateway | HMAC-SHA256 signing and verification of server-side operator assertions |
| `DECISION_SERVICE_API_KEY` | API gateway and decision service | Internal decision-service authentication |

Each value must be at least 32 bytes and all five must be unique. The API gateway checks this at production startup. The dashboard and NAD processor also validate their own workload credentials.

## 2. First-run administrator setup

From the repository root:

```bash
./scripts/setup_credentials.sh
```

Choose the administrator username and password. Supply the value configured as `CYBERGUARDIAN_API_KEY` in the deployment environment when prompted, or use the generated value and copy it into the environment file. The gateway refuses production startup if the environment key and credential-store key do not match.

Copy `deploy/docker/.env.example` to the deployment's private `.env`, replace every placeholder with its independently generated value, and set:

- `CG_PRODUCTION=1`
- `CG_COOKIE_SECURE=1`
- `CG_DATA_HOST_DIR` to a persistent directory outside the repository
- `CG_TRUSTED_PROXY_IPS` to the exact reverse-proxy IP/CIDR values, or leave it empty if no proxy supplies forwarding headers

Do not commit `.env`, `credentials.json`, database files, or backups.

## 3. Operator onboarding and role assignment

Use the CLI from the repository root. Passwords are prompted interactively and never passed in command-line arguments:

```bash
python3 scripts/manage_dashboard_user.py \
  --username operator-alice \
  --tenant-id client-a \
  --role operator
```

Supported roles are:

- `admin`: tenant administrator; can change client mode and perform operator actions.
- `operator`: can approve/reject staged actions and request rollback within the assigned tenant.
- `analyst`: read-only dashboard access.
- `viewer`: read-only dashboard access.

To rotate a user's password or change their role/tenant, repeat the command with `--replace`. The utility hashes passwords with PBKDF2-HMAC-SHA256 and atomically writes `credentials.json` with restrictive permissions. It does not print or store the plaintext password.

For a deployment using a non-default data directory, set `CG_DATA_DIR` to that directory before running the CLI. Only an authorized system administrator should run this utility.

## 4. TLS reverse-proxy requirements

The Compose file binds the dashboard and API host ports to loopback. Keep the API port private; expose the dashboard through a TLS-terminating reverse proxy.

- Keep `CG_COOKIE_SECURE=1` in production. Production startup fails if Secure cookies are disabled.
- Set `CG_TRUSTED_PROXY_IPS` to only the proxy's actual IP/CIDR. Do not trust broad private networks unless every host in that range is controlled.
- Configure the edge proxy to discard client-supplied forwarding headers and set/append its own `X-Forwarded-For` chain.
- Do not publish the API or decision-service ports to the public Internet.
- Keep CORS origins explicit and limited to the real dashboard origin.
- HSTS is emitted when Secure-cookie mode is enabled; only enable this on a domain that is consistently served over HTTPS.

The application ignores `X-Forwarded-For` from peers not present in `CG_TRUSTED_PROXY_IPS`.

## 5. Secret rotation

Coordinate changes so both sides of each service relationship are updated together:

1. Back up the persistent data directory and private environment file.
2. Generate a new independent value with `openssl rand -hex 32`.
3. Update the matching environment variable and every service that consumes it:
   - Dashboard key: API gateway + dashboard.
   - NAD key: API gateway + NAD processor.
   - Operator assertion secret: API gateway + dashboard. Stop both services during the change so they cannot disagree.
   - Decision-service key: API gateway + decision service.
   - Administrator key: API gateway environment + `api_key` in `credentials.json`.
4. Restart the affected services and verify health, login, operator proxy requests and audit attribution.
5. Confirm the old value is no longer present in deployment configuration or secret stores. Never paste secrets into logs or PR comments.

The API gateway rejects production startup when the five values are weak, missing or reused.

## 6. Persistent data backup and restore

The Compose data volume contains the credential store, dashboard session database, gateway database, gate configuration and operator assertion replay database. Back up the entire data directory, not just one SQLite file.

For a consistent live SQLite backup, use Python's SQLite backup API:

```bash
export CG_DATA_DIR=/path/to/persistent/cyberguardian-data
export BACKUP_DIR=/path/to/encrypted-backups/cyberguardian-$(date +%Y%m%d-%H%M%S)
mkdir -m 700 -p "$BACKUP_DIR"
python3 - <<'PY'
import os
import shutil
import sqlite3
from pathlib import Path

source = Path(os.environ["CG_DATA_DIR"])
target = Path(os.environ["BACKUP_DIR"])
for src_path in source.rglob("*"):
    if not src_path.is_file():
        continue
    relative = src_path.relative_to(source)
    dst_path = target / relative
    dst_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if src_path.suffix in {".sqlite3", ".db"}:
        src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
        dst = sqlite3.connect(dst_path)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()
    else:
        shutil.copy2(src_path, dst_path)
    dst_path.chmod(0o600)
PY
```

Encrypt and store backups in an access-controlled location. Restore only while the application services are stopped; restore the complete set together, then verify file ownership and restrictive permissions before restarting. Retain the replay-nonce database during restore. If it cannot be restored, keep the gateway offline for at least 65 seconds before accepting dashboard assertions so any previously issued 60-second assertion has expired.

## 7. Audit ledger integrity and export

Every gateway audit write is also appended to `audit_ledger.jsonl` in the persistent data directory. The ledger is hash-chained, serialized with an advisory lock, written with append + fsync, and stored with owner-only permissions. The gateway refuses to extend a ledger whose existing chain fails verification; audit persistence failure is treated as a failed request rather than silently ignored.

Verify the ledger from the repository root:

```bash
CG_DATA_DIR=/path/to/persistent/cyberguardian-data \
  python3 scripts/verify_audit_ledger.py
```

The command reports the record count and current chain head and exits non-zero if a record is truncated, altered, or out of sequence. Run it after restore and as part of regular audit review. Include the ledger and its lock file in protected backups.

Export a consistent, integrity-verified snapshot to a protected destination:

```bash
CG_DATA_DIR=/path/to/persistent/cyberguardian-data \
  python3 scripts/export_audit_ledger.py --out /path/to/encrypted-export/audit-ledger.jsonl
```

The export prints a manifest containing the record count, chain head, byte count and SHA-256 digest. The destination is created atomically with owner-only permissions. Transfer the export to independently administered immutable storage/SIEM using your organization's approved secure process.

**Integrity limitation:** a local hash chain detects accidental corruption and unauthorized edits that do not also rewrite the chain. It is not a defense against a privileged attacker who can replace the ledger and application code. For stronger assurance, periodically export signed checkpoints or the ledger itself to an independently administered, append-only remote log/SIEM. Retention, remote export and external checkpoint signing remain R4 work.

## 8. Tenant-scoped weekly client report export

Set the API key and tenant explicitly. The script refuses to generate a report without a tenant or when either the weekly report or scorecard source is unavailable.

```bash
CYBERGUARDIAN_API=http://127.0.0.1:8080 \
CYBERGUARDIAN_API_KEY="$CYBERGUARDIAN_API_KEY" \
CYBERGUARDIAN_TENANT="client-a" \
python3 scripts/weekly_client_pdf.py \
  --client "Client A" \
  --out ./reports/client-a-weekly.pdf \
  --csv-out ./reports/client-a-scorecard.csv
```

The PDF includes the tenant and generation timestamp. CSV export contains scorecard checks, is written atomically with owner-only permissions, and prefixes spreadsheet-formula-like values to reduce CSV injection risk. Store exports only in the tenant's approved document location and apply the client's retention/access policy.

## 9. Operational security checks

Before enabling a client tenant:

- Verify all workload credentials are distinct and only present in the intended containers.
- Verify a dashboard login and logout, CSRF rejection, role denial, tenant scoping, audit attribution and replay rejection.
- Verify NAD cannot read fleet or administrative routes and can only submit detections.
- Verify decision-service calls fail without the internal key.
- Verify the reverse proxy's actual peer address is included in `CG_TRUSTED_PROXY_IPS`.
- Verify backups are encrypted, access-controlled and restorable.

Passing CI and Compose acceptance is not a substitute for the final isolated VM/Termux and client-network validation described in the release handover.
