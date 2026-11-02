# Gateway packaging status

## Preferred (complete source)

Base64 parts under `gateway_b64/p000.b64` … + `decode_gateway_b64.py`:

```bash
cd control-plane/api
python3 decode_gateway_b64.py   # writes main_full.py
```

Expected SHA256 of main_full.py:
`39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674`

Also: plain `gw_src_*.txt` + `assemble_main.py` when all fragments are present.

Bootstrap `main.py` loads `main_full.py` or assembles from fragments.

## Operator note

If `decode_gateway_b64.py` fails with missing parts, copy from release tarball
`cyberguardian-p0-gateway-src.tgz` or push remaining `gateway_b64/p*.b64` files.
