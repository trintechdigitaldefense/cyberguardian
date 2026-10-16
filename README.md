# CyberGuardian

**Supervised self-healing cybersecurity control plane + Linux agent**  
**v1.1.0-pilot** · TrinTech Digital Defense (Trinidad & Tobago)

[![License: Authorized Use](https://img.shields.io/badge/license-authorized%20use%20only-blue)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

CyberGuardian coordinates detection, human-gated response, issue memory, fleet visibility, network inventory, and operator reporting for Linux environments **without a full SOC**.

> **Not** a 24/7 SOC replacement, full Windows/macOS EDR, or open-ended autonomous AI.  
> Default posture: **Client Mode ON** — isolate / kill / block require human approval.

---

## Architecture

| Service | Port | Role |
|---------|------|------|
| Decision Service | 8001 | Risk scoring, playbooks, protection mode |
| API Gateway | 8080 | Assets, detections, gate, issues, fleet, inventory |
| NAD Processor | 8002 | Anomaly helpers / simulation (pilot) |
| **Dashboard** | **3000** | Operator UI — login, Client Mode, gate approve/reject, fleet, issues, inventory |
| Linux Agent | — | Process / baseline scans, offline queue |

**Loop:** Detection → risk / playbook → stage (Client Mode ON) or known-playbook auto-remediate (OFF) → issue memory → audit / reports.

```
Agent --(agent key)--> API /v1/detections
                           |
                           v
                     Decision /v1/decide
                           |
           +---------------+---------------+
           | Client Mode ON                | Client Mode OFF
           v                               v
     pending_actions (gate)         known-playbook execute
           |                               |
           v                               v
     Dashboard approve/reject        issue_memory auto_fixed
```

---

## Dashboard (fully wired)

After login at `http://<host>:3000` the operator can:

| UI panel | Backend |
|----------|---------|
| Summary cards (assets, online, detections, pending, Client Mode) | `/v1/risk/summary`, `/v1/fleet`, `/v1/gate`, `/v1/client-mode` |
| Client Mode ON / OFF | `POST /v1/client-mode` |
| Human Gate — Approve / Reject | `POST /v1/gate/approve/{id}`, `POST /v1/gate/reject/{id}` |
| Remembered Issues | `GET /v1/issues/client-view` |
| Fleet table | `GET /v1/fleet` |
| Inventory report | `GET /v1/inventory/report` |
| Connectivity badge | API health probe |

Dashboard proxies (session cookie required):

- `GET/POST /ops/client-mode`
- `GET /ops/gate` · `POST /ops/gate/approve/{id}` · `POST /ops/gate/reject/{id}`
- `GET /ops/issues` · `GET /ops/fleet` · `GET /ops/risk` · `GET /ops/inventory`
- `GET /ops/status`

---

## Features (pilot)

- **Dual API keys** — admin (gate, Client Mode) ≠ agent (register, detections, remember)
- **Client Mode** — default ON; disruptive actions staged for human approval
- **Issue memory** — persistent fingerprints; auto-remediate only for known playbooks when Client Mode OFF
- **Offline queue** — agent continues when controller is unreachable
- **Human gate** — approve / reject from the dashboard
- **Playbooks** — credential theft, ransomware, C2 beacon
- **Fleet + inventory** — registered assets, last-seen, best-effort discovery report
- **Dry-run + health scripts** — verify before client networks

---

## Quick start

```bash
# 1) Python 3.10+
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) First-run credentials (writes data/credentials.json mode 600)
./scripts/setup_credentials.sh

# 3) Start stack
./start.sh

# 4) Verify
./scripts/client_health.sh
./scripts/dry_run_pilot.sh
```

| URL | Purpose |
|-----|--------|
| http://\<host\>:3000 | Dashboard (login required) |
| http://127.0.0.1:8080/health | API health |
| http://127.0.0.1:8001/health | Decision health |

Login is whatever you set in `setup_credentials.sh` (no hardcoded lab passwords in the repo).

---

## Agent on a Linux host

```bash
export CYBERGUARDIAN_API=http://CONTROLLER_IP:8080
export CYBERGUARDIAN_API_KEY="<agent_api_key from credentials.json>"
export CG_CONTROLLER_URL=http://CONTROLLER_IP:8080
python3 agents/linux-ebpf/agent.py --interval 60
```

Use the **agent** key on endpoints. Use the **admin** key only for dashboard/ops/gate.

---

## Client Mode

| Mode | Behaviour |
|------|----------|
| **ON** (default) | Disruptive actions staged; auto-remediate blocked |
| **OFF** | Known-playbook auto-remediate may run |

```bash
curl -X POST -H "X-API-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"client_mode":true}' http://127.0.0.1:8080/v1/client-mode
```

Or toggle from the dashboard.

---

## Project layout

```
CyberGuardian/
├── agents/linux-ebpf/     # Protective agent + offline queue
├── control-plane/
│   ├── api/               # Gateway (dual-key auth, gate, issues, fleet)
│   ├── decision-service/  # Risk + playbooks
│   ├── nad-processor/     # Simulation helpers
│   ├── tie/ · compliance/ # Pilot stubs
├── dashboard/             # Operator UI (proxies to API)
├── scripts/               # setup_credentials, dry_run, health
├── docs/                  # PILOT_SCOPE, ARCHITECTURE
├── start.sh · stop.sh
└── requirements.txt
```

---

## Pilot honesty

See [docs/PILOT_SCOPE.md](docs/PILOT_SCOPE.md).

- Linux visibility + supervised response — **not** a full SOC or EDR for every OS
- Auto-remediate uses **known playbooks only**
- Control plane must not be exposed to the public internet
- Residual risk remains with the client’s broader controls

---

## License

Authorized defensive use only — TrinTech Digital Defense. See [LICENSE](LICENSE).

**Contact:** trintechdigitaldefense@gmail.com · +1 (868) 362-0679 · [github.com/trintechdigitaldefense](https://github.com/trintechdigitaldefense)
