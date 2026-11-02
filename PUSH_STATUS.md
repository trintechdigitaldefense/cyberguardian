# Push status — P0 packaging

## On GitHub now

- `control-plane/api/main.py` — fail-loud bootstrap (assembles `gw_src_*.txt`)
- `control-plane/api/assemble_main.py` — concatenates fragments → `main_full.py`
- `control-plane/api/GATEWAY_SHA256.txt` — expected sha256 of full gateway
- `control-plane/api/gw_src_12.txt` — last fragment
- `scripts/ci_import_api.sh` — import smoke test
- `start.sh` — fails if assemble fails

## Still required (close P0 #1)

Push **all** fragments from the build machine that has the full tree:

```bash
cd /path/to/CyberGuardian   # local artifacts with gw_src_00..12

git add control-plane/api/gw_src_*.txt \
        control-plane/api/assemble_main.py \
        control-plane/api/main.py \
        control-plane/api/GATEWAY_SHA256.txt \
        scripts/ci_import_api.sh \
        start.sh

git commit -m "P0: full API gateway plain source (gw_src_00..12)"
git push origin main

# cleanup obsolete broken packaging
git rm -rf control-plane/api/gateway_parts control-plane/api/main_b64 2>/dev/null || true
git commit -m "P0: remove obsolete zlib gateway_parts" || true
git push origin main
```

## Acceptance

```bash
git clone https://github.com/trintechdigitaldefense/cyberguardian.git
cd cyberguardian
python3 control-plane/api/assemble_main.py
sha256sum control-plane/api/main_full.py
# expect: 13ddc6fd897fcb519a79e2690d56616db737d1fb736e77bd32661d04818c38fe
bash start.sh
curl -sS http://127.0.0.1:8080/health
```

Fragment count: **13 files** `gw_src_00.txt` … `gw_src_12.txt` (~51.5KB assembled).
