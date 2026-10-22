# Push status — CyberGuardian 1.3.0-tier2

**Date:** 2026-10-22

## On main

- VERSION 1.3.0-tier2
- CHANGELOG Tier 1 + Tier 2
- agents/linux-ebpf/agent.py (containment poll + identity)
- agents/linux-ebpf/containment.py
- agents/linux-ebpf/offline_queue.py
- control-plane/decision-service/main.py (evidence)
- dashboard/main.py (audit/scorecard/weekly ops)
- scripts/pilot_day1.sh, weekly_digest.sh
- configs/auto_allowlist.yaml
- control-plane/api/allowlist.py, agent_identity.py, sentinel_bridge.py

## May still lag local tree

- control-plane/api/main.py (full Tier 1+2 gateway — large file; local is source of truth)
- dashboard/templates/index.html (evidence + audit UI)
- README.md full Tier 2 section

Local path: `/home/workdir/artifacts/CyberGuardian`

```bash
# Prefer syncing local main.py + index.html if clone lacks them
./scripts/pilot_day1.sh
```
