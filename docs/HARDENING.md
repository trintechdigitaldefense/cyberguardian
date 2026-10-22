# CyberGuardian — Hardened deploy defaults

Authorized defensive use only. For Trinidad & Tobago / Caribbean SMB pilots.

## Default posture

| Setting | Default | Why |
|---------|---------|-----|
| Client Mode | **ON** | Isolate / kill / block need human approval |
| API bind | **127.0.0.1** when CG_HARDENED=1 | Avoid accidental public exposure |
| Dual API keys | Required | Agent key ≠ admin key |
| Auto-remediate | Allowlist only (`lab`/`dev`) when Client Mode OFF | Production tags hard-denied |
| isolate_host auto | **Off** in allowlist | Too disruptive for unsupervised |

## Before any client network

1. Run `./scripts/pilot_day1.sh` and confirm scorecard is mostly green.
2. Confirm Client Mode **ON** in the dashboard.
3. Do **not** publish ports 8080 / 3000 / 8001 to the public internet.
4. Prefer SSH tunnel or VPN for operator access:

```bash
ssh -L 3000:127.0.0.1:3000 -L 8080:127.0.0.1:8080 user@controller
```

5. Put TLS termination on a reverse proxy (Caddy / nginx) if operators need HTTPS.
6. `data/credentials.json` mode `600`; never commit it.
7. Agent uses **agent** key only; admin key stays on the controller/operator machine.

## start.sh production hints

```bash
export CG_HARDENED=1
./start.sh
```

When `CG_HARDENED=1`, services bind localhost only.

## Residual risk

CyberGuardian is a **supervised** pilot control plane. It does not replace backups, patching, identity hygiene, or a full SOC.
