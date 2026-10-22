# API main.py source of truth

The full Tier 1–3 API gateway lives in the operator workspace copy of this repo
(`control-plane/api/main.py`, ~51KB).

GitHub Contents API pushes of this single file can hit size limits from the
automation path. To sync onto a clone from the complete local tree:

```bash
cp control-plane/api/main.py /path/to/clone/control-plane/api/main.py
git add control-plane/api/main.py
git commit -m "v1.4.0-tier3: full API gateway"
git push
```

Includes: dual keys, client mode, gate, agent command queue, audit, allowlist,
identity, sentinel bridge, rollback, false-positive feedback, pilot scorecard,
weekly digest.

Related modules (already on main):

- allowlist.py, agent_identity.py, sentinel_bridge.py, fp_feedback.py, issue_memory.py
