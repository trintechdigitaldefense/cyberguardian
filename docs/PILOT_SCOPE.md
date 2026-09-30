# CyberGuardian — Supervised Pilot Scope

**Vendor:** TrinTech Digital Defense  
**Product:** CyberGuardian (optional: Mirage / Sentinel on the same engagement)

## What this pilot IS

- Linux host visibility via Guardian agent (process / FIM / baseline best-effort)
- Detection → risk decision → **Human Gate** when Client Mode is ON
- Remembered issues for operator review
- Network inventory (best-effort LAN discovery — not a full CMDB)
- Operational / biweekly-style reporting when configured
- Offline queue when the controller is unreachable

## What this pilot is NOT

- Not a 24/7 SOC replacement
- Not full Windows / macOS EDR coverage
- Not guaranteed prevention of all breaches
- Not open-ended AI that invents novel fixes (auto-remediate uses **known playbooks** only)
- Not a substitute for firewall, email security, backups, or patch management

## Default safety posture

- **Client Mode ON** for client networks
- Disruptive actions (isolate / kill / block) require human approval
- Agent API key ≠ admin API key
- Control plane should not be exposed to the public internet

## Success criteria

- Services healthy; Client Mode ON
- `scripts/dry_run_pilot.sh` shows auto-remediate **blocked**
- At least one agent online when deployed
- Scope shared with the client in writing

## Honesty clause

CyberGuardian improves visibility and response discipline on covered Linux assets. Residual risk remains with the client’s broader controls.
