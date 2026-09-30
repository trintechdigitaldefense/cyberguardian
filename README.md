# CyberGuardian

**Supervised self-healing cybersecurity control plane + Linux agent**  
TrinTech Digital Defense (Trinidad & Tobago)

[![License: Authorized Use](https://img.shields.io/badge/license-authorized%20use%20only-blue)](LICENSE)

CyberGuardian coordinates detection, human-gated response, issue memory, fleet visibility, network inventory, and client reporting for Linux environments without a full SOC.

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
export CG_CONTROLLER_URL=http://CONTROLLER_IP:8080
python3 agents/linux-ebpf/agent.py --interval 60
```

Use the **agent** key on endpoints. Use the **admin** key only for dashboard/ops/backup/gate.

## Client Mode

| Mode | Behaviour |
|------|-----------|
| **ON** (default) | Disruptive actions staged for human approval; auto-remediate blocked |
| **OFF** | Known-playbook auto-remediate may run for eligible remembered issues |

## Security notes

- Never commit `data/credentials.json`, databases, or TLS keys (see `.gitignore`).
- Do not expose ports 3000/8080/8001 to the public internet.
- Authorized defensive use and authorized testing only.

## Relationship to Sentinel / Mirage

- **Sentinel** — deep single-host Line of Defense (FIM, SSH block, hardening, deception).
- **Mirage** — network deception grid.
- **CyberGuardian** — multi-host control plane, human gate, fleet + client reporting.

Best stack: Sentinel (and/or Mirage) on hosts + CyberGuardian as the brain.

## License

Authorized defensive / authorized testing use only. See [LICENSE](LICENSE).

---

TrinTech Digital Defense · [GitHub](https://github.com/trintechdigitaldefense) · Trinidad & Tobago
