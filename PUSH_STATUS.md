# R2 1.6.0-security push status

## On GitHub branch

- `command_crypto.py` (P5 verify before execute)
- bootstrap `main.py`, Dockerfile assemble, CI docker job
- `assemble_main.py` prefers `gateway_hex`
- GATEWAY_SHA256 = `09fb7d3bc9019aa4604a5b2d1b5df6f607b73d2e487332bddeebedf1547e9f80`
- Partial `gateway_hex` (00, 01, 05, 10, 11)

## Complete local tree

`/tmp/cg-r2` and `/home/workdir/artifacts/CyberGuardian`

```bash
cd /tmp/cg-r2
git remote -v
git add -A
git status
git commit -m "R2: full security tree + gateway_hex complete"
git push origin r2-1.6.0-security
```

Required remaining files:
- control-plane/api/gateway_hex/c0.hex … c3.hex (or 00–11.hex)
- agents/linux-ebpf/agent.py containment.py offline_queue.py
- dashboard/main.py
- start.sh status.sh stop.sh
- control-plane/decision-service/main.py
- control-plane/api/agent_identity.py
- scripts/setup_credentials.sh
- tests/*

## Verify after full push

```bash
git clone -b r2-1.6.0-security https://github.com/trintechdigitaldefense/cyberguardian.git
cd cyberguardian
python3 control-plane/api/assemble_main.py
python3 -m pytest tests/ -q
bash start.sh && bash status.sh
```
