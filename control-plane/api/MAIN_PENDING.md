# Full API gateway — push from your machine

Automation cannot upload the complete ~52KB `main.py` via the Contents API without corruption.

**Source of truth (local):**

```
/home/workdir/artifacts/CyberGuardian/control-plane/api/main.py
```

Or tarball: `artifacts/cyberguardian-api-main-1.5.1.tgz`

## One command (closes the clone gap)

```bash
cd /home/workdir/artifacts/CyberGuardian
git add control-plane/api/main.py
git commit -m "v1.5.1: full API gateway main.py"
git push origin main
```

After push, delete leftover junk if still present:

```bash
git rm -f control-plane/api/gateway_parts/chunk*.z64 2>/dev/null
git rm -rf control-plane/api/main_b64 2>/dev/null
git commit -m "cleanup: remove failed upload fragments" || true
git push
```

Until then: run from the local tree with `./start.sh` — local main.py is complete.
