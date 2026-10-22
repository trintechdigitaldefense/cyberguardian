# Push status — CyberGuardian 1.2.0-tier1

**Date:** 2026-10-22

## Pushed to main

- VERSION → 1.2.0-tier1
- CHANGELOG.md (Tier 1 section)
- agents/linux-ebpf/agent.py (poll + execute containment)
- agents/linux-ebpf/offline_queue.py
- scripts/pilot_day1.sh
- scripts/weekly_digest.sh

## Still need full push (local tree is source of truth)

Local path: `/home/workdir/artifacts/CyberGuardian`

| Path | Why |
|------|-----|
| agents/linux-ebpf/containment.py | **New** — real kill/isolate/block |
| control-plane/api/main.py | Command queue, audit, scorecard, weekly |
| control-plane/decision-service/main.py | Evidence object |
| dashboard/main.py | ops/audit, scorecard, weekly |
| dashboard/templates/index.html | Audit + scorecard UI + evidence |
| README.md | Tier 1 feature list |

After these land, delete `control-plane/api/MAIN_PENDING.md` if still present.

## Verify

```bash
git clone https://github.com/trintechdigitaldefense/cyberguardian.git
# merge local tree or pull remaining files
./scripts/pilot_day1.sh
```
