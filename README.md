# CyberGuardian

**Supervised self-healing cybersecurity control plane + Linux agent**  
**v1.1.0-pilot** · TrinTech Digital Defense (Trinidad & Tobago)

[![License: Authorized Use](https://img.shields.io/badge/license-authorized%20use%20only-blue)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

CyberGuardian coordinates detection, human-gated response, issue memory, fleet visibility, network inventory, and client reporting for Linux environments **without a full SOC**.

> **Not** a 24/7 SOC replacement, full Windows/macOS EDR, or open-ended autonomous AI.  
> Default posture: **Client Mode ON** — isolate / kill / block require human approval.

## Architecture

| Service | Port | Role |
|---------|------|------|
| Decision Service | 8001 | Risk scoring, playbooks, protection mode |
| API Gateway | 8080 | Assets, detections, gate, issues, fleet, reports |
| NAD Processor | 8002 | Anomaly helpers / simulation |
| Dashboard | 3000 | Operator UI (login required) |
| Linux Agent | — | Process / FIM / baseline scans, offline queue |

**Loop:** Detection → risk / playbook → stage (Client Mode ON) or known-playbook auto-remediate (OFF) → issue memory → audit / reports.

## Features (pilot)

- **Dual API keys** — admin vs agent least privilege
- **Client Mode** — disruptive actions staged for human approval (default ON)
- **Issue memory** — persistent fingerprints; known playbooks only for auto-remediate
- **Offline queue** — agent continues when controller is unreachable
- **Fleet + inventory** — registered assets, last-seen, best-effort LAN discovery
- **Human gate** — approve / reject pending isolate / kill / block
- **Playbooks** — credential theft, ransomware, C2 beacon patterns
- **Dashboard** — login, client-mode toggle, issues, fleet
- **Dry-run + health scripts** — pilot verification before client networks

## Quick start (local)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./scripts/setup_credentials.sh
./start.sh
./scripts/client_health.sh
./scripts/dry_run_pilot.sh
```

- Dashboard: `http://<host>:3000`
- API: `http://<host>:8080/health`

## Agent on a Linux host

```bash
export CYBERGUARDIAN_API=http://CONTROLLER_IP:8080
export CYBERGUARDIAN_API_KEY="<agent_api_key from credentials.json>"
python3 agents/linux-ebpf/agent.py --interval 60
```

## Client Mode

| Mode | Behaviour |
|------|-----------|
| **ON** (default) | Disruptive actions staged for human approval; auto-remediate blocked |
| **OFF** | Known-playbook auto-remediate may run for eligible remembered issues |

## Pilot scope

See [docs/PILOT_SCOPE.md](docs/PILOT_SCOPE.md). Control plane must **not** be exposed to the public internet.

## License

Authorized defensive security use only. See [LICENSE](LICENSE).

**TrinTech Digital Defense** · Trinidad & Tobago  
https://trintechdigitaldefense.github.io · trintechdigitaldefense@gmail.com
