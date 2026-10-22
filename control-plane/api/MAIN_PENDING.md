# Full API gateway (clone gap)

Complete `main.py` (~51KB, Tier 1–3 + strength) exceeds the Contents API push limit from automation.

**Source of truth:** local tree or `cyberguardian-1.5.1-strength.tgz`

```bash
cp control-plane/api/main.py /path/to/clone/control-plane/api/main.py
cd /path/to/clone && git add control-plane/api/main.py
git commit -m "v1.5.1: full API gateway" && git push

# Or assemble from parts after they are on disk:
python3 control-plane/api/assemble_main.py
```

`./start.sh` runs assemble when `main.py.part*` exist.

Includes: dual keys, client mode, gate, command queue, audit, allowlist, strict identity option, sentinel, rollback, FP feedback, WAL, scorecard, weekly digest.
