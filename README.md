# CyberGuardian

**Supervised self-healing cybersecurity control plane + Linux agent**  
**v1.4.0-tier3** · TrinTech Digital Defense (Trinidad & Tobago)

Detect → Decide → **Approve** → Contain → Audit.

> **Not** a 24/7 SOC, full multi-OS EDR, or open-ended autonomous AI.  
> Default: **Client Mode ON** — isolate / kill / block need human approval.

---

## Architecture

| Service | Port | Role |
|---------|------|------|
| Decision Service | Internal 8001 | Risk scoring, playbooks, evidence; no host-published port in Compose |
| API Gateway | 8080 | Gate, command queue, audit, allowlist, identity, FP feedback |
| Dashboard | **3000** | Operator UI (fully proxied to API) |
| Linux Agent | — | Detect, poll commands, real containment |

```
Agent --(agent key)--> API /v1/detections
                           |
                     Decision /v1/decide
                           |
           Client Mode ON  |  Client Mode OFF + allowlist
           pending gate    |  auto-queue to agent
           Dashboard approve --> agent executes (kill/isolate/block)
```

---

## Dashboard wiring (all operator actions)

| UI | Backend |
|----|---------|
| Client Mode ON/OFF | `POST /v1/client-mode` |
| Gate Approve / Reject | `POST /v1/gate/approve|reject/{id}` |
| **Mark benign** | `POST /v1/feedback/benign` (14d suppress) |
| **Undo isolate** | `POST /v1/rollback/{asset_id}` |
| Audit trail | `GET /v1/audit` |
| Pilot scorecard | `GET /v1/pilot/scorecard` |
| Weekly digest | `GET /v1/reports/weekly` |
| Fleet + inventory | `GET /v1/fleet`, `/v1/inventory/report` |

Dashboard proxies (session required): `/ops/client-mode`, `/ops/gate/*`, `/ops/audit`, `/ops/scorecard`, `/ops/weekly`, `/ops/rollback/{id}`, `/ops/feedback/benign`, `/ops/fleet`, `/ops/hardening`. Dashboard sessions are persistent and expiring; passwords are PBKDF2-hashed; login throttling, CSRF checks, role checks, and tenant propagation are enabled.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./scripts/setup_credentials.sh

# Hardened (localhost only) — recommended for pilots
export CG_HARDENED=1
./start.sh

./scripts/pilot_day1.sh
```

| URL | Purpose |
|-----|--------|
| http://127.0.0.1:3000 | Dashboard |
| http://127.0.0.1:8080/health | API |

SSH tunnel if remote: `ssh -L 3000:127.0.0.1:3000 -L 8080:127.0.0.1:8080 user@host`

## Hardened Docker Compose deployment

Run `./scripts/setup_credentials.sh` first. It writes a PBKDF2 password hash and the API keys into the ignored `data/credentials.json` file. Then create a private `deploy/docker/.env` file:

```bash
CYBERGUARDIAN_API_KEY=<the admin API key printed by setup_credentials.sh>
CG_DASHBOARD_API_KEY=<the distinct dashboard key printed by setup_credentials.sh>
CG_NAD_API_KEY=<the distinct NAD key printed by setup_credentials.sh>
CG_OPERATOR_ASSERTION_SECRET=<the distinct operator secret printed by setup_credentials.sh>
DECISION_SERVICE_API_KEY=<the distinct decision-service key printed by setup_credentials.sh>
CG_PRODUCTION=1
CG_REQUIRE_AGENT_IDENTITY=1
CG_COOKIE_SECURE=1
CG_ALLOWED_ORIGINS=https://your-dashboard.example
CG_DATA_HOST_DIR=../../data
```

Keep every service secret and `.env` private; never commit them. All five administrator/service/signing values must be unique and at least 32 bytes. Compose injects the decision-service key into both the API gateway and decision service, and keeps dashboard, NAD and operator identities separate. Compose publishes the dashboard and API only on loopback; the decision service is reachable only on the private Compose network. For remote access, use an SSH tunnel or a TLS reverse proxy and set `CG_ALLOWED_ORIGINS` to the exact HTTPS dashboard origin.

See [docs/HARDENING.md](docs/HARDENING.md) for the full production configuration and [docs/ROADMAP.md](docs/ROADMAP.md) for phase status.

> **Note:** On first start, `assemble_main.py` rebuilds `control-plane/api/main.py` from `main.py.part1` + `main.py.part2` if needed (GitHub file-size workaround).

---

## Agent

```bash
export CYBERGUARDIAN_API=http://CONTROLLER:8080
export CYBERGUARDIAN_API_KEY="<agent_api_key>"
export CYBERGUARDIAN_TAGS=lab,dev   # optional; only for allowlisted auto when CM OFF
python3 agents/linux-ebpf/agent.py --interval 60
```

---

## Safety model

| Feature | Behaviour |
|---------|----------|
| Client Mode ON | Disruptive actions staged for human approval |
| Allowlist | When CM OFF: only lab/dev/staging; production tags denied |
| Containment | Real SIGTERM/SIGKILL, nft/iptables (root for network) |
| Rollback | Undo isolate via agent restore_network |
| FP feedback | Mark benign → suppress restaging 14 days |
| Identity | Per-agent fingerprint + HMAC; mandatory for production enrollment |

See [docs/HARDENING.md](docs/HARDENING.md) and [docs/PILOT_SCOPE.md](docs/PILOT_SCOPE.md).

---

## License

Authorized defensive use only — TrinTech Digital Defense.  
**Contact:** trintechdigitaldefense@gmail.com · +1 (868) 362-0679
