# API gateway packaging (updated)

The full gateway source is split into plain-text parts (no compression):

- `main_part0.py.txt`
- `main_part1.py.txt`
- `main_part2.py.txt`

On start, `main.py` concatenates these into `_assembled_main.py` (or uses `main_full.py` if present).

```bash
python3 control-plane/api/assemble_main.py   # writes main_full.py
```

Obsolete zlib `gateway_parts/*.z64` and `main_b64/` are deprecated — do not use.

Acceptance: clean clone + `python3 -c "from control_plane..."` or start API without external tarballs.
