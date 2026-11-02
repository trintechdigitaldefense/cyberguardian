# API gateway packaging (P0)

## Source of truth

Plain fragments (no compression):

- `gw_src_00.txt` … `gw_src_12.txt`

Assemble:

```bash
python3 control-plane/api/assemble_main.py   # writes main_full.py
```

Bootstrap `main.py` concatenates fragments at import if `main_full.py` is absent.

## Verify

```bash
python3 control-plane/api/assemble_main.py
sha256sum control-plane/api/main_full.py
# expect: 13ddc6fd897fcb519a79e2690d56616db737d1fb736e77bd32661d04818c38fe
python3 scripts/ci_import_api.sh
```

## Obsolete

Do not use `gateway_parts/*.z64` or `main_b64/`.
