# Full API gateway — clone gap

The complete `main.py` (~52KB) cannot be uploaded via the GitHub Contents API from the automation path.

## Close the gap (one command on your machine)

```bash
# Option A — from the workspace tree
cd /home/workdir/artifacts/CyberGuardian
git remote -v   # ensure origin is trintechdigitaldefense/cyberguardian
git add control-plane/api/main.py
git commit -m "v1.5.1: full API gateway main.py"
git push origin main

# Option B — from the release tarball
tar xzf cyberguardian-api-main-1.5.1.tgz
cp control-plane/api/main.py /path/to/clone/control-plane/api/main.py
cd /path/to/clone && git add control-plane/api/main.py && git commit -m "v1.5.1: full API gateway" && git push
```

Until that lands, **run from the local tree** (`./start.sh`) — local `main.py` is complete (queue, audit, identity, rollback, FP, WAL).

Optional: `main_loader.py` + `gateway_parts/` assemble the same source if you prefer split files.
