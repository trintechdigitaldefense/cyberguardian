# R2 push status

Branch: `r2-1.6.0-security`

## On branch

- Docker assemble + SHA path
- main.py bootstrap
- stop.sh PID ownership
- VERSION 1.6.0-r2
- TEN_MINUTE_TEST_REPORT (16/16 PASS)
- GATEWAY_SHA256 updated to `c83c76cba8256f0d0e8de1026b5d404667c8020b902b51cbec7613c8dc302dfb`

## Must complete from build tree (`/tmp/cg-r2` or artifacts)

Push remaining files so branch is complete:

```bash
cd /tmp/cg-r2   # or your R2 worktree
git remote add origin https://github.com/trintechdigitaldefense/cyberguardian.git 2>/dev/null || true
git checkout r2-1.6.0-security
git add -A
git status
git commit -m "R2: containment, dashboard auth, offline queue, identity, tests, gateway_z full"
git push -u origin r2-1.6.0-security
```

Critical paths:
- control-plane/api/gateway_z/00-05.txt (full set matching new SHA)
- control-plane/api/assemble_main.py
- start.sh status.sh
- agents/linux-ebpf/containment.py offline_queue.py
- dashboard/main.py
- control-plane/api/agent_identity.py
- control-plane/decision-service/main.py
- tests/* scripts/ten_minute_test.sh

Then open PR into main.
