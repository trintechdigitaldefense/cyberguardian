# API Gateway `main.py`

The full `control-plane/api/main.py` (~22KB) is included in the **v1.1.0-pilot** release tarball and the local pilot tree.

**Why:** GitHub file write size limits in this automated push path.

**To complete the clone:**

```bash
# Option A — from release asset / local tarball
tar xzf CyberGuardian-v1.1.0-pilot.tar.gz
# Option B — copy from a machine that has the full tree
cp /path/to/CyberGuardian/control-plane/api/main.py control-plane/api/
```

After copy, `./start.sh` runs the full stack.

All other pilot sources (agent, decision service, dashboard, issue memory, scripts, docs) are already on `main`.
