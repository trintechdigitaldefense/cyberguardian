# Push status v1.5.1-strength

## Blocker

`control-plane/api/main.py` on GitHub may still be a thin loader (~1KB). Full gateway (~52KB) lives on the build machine / tarball.

**Close gap:** from the machine that has the full tree:

```bash
git add control-plane/api/main.py
git commit -m "v1.5.1: full API gateway main.py"
git push origin main
```

## Do not push

- `data/credentials.json` (passwords, API keys)

## See also

- `docs/OPERATIONAL_NEXT.md`
