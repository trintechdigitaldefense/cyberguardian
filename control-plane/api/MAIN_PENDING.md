# API gateway assembly

Full gateway is split for GitHub size limits:

- `main.py.part1`
- `main.py.part2`
- `assemble_main.py` — run by `start.sh` before uvicorn

```bash
python3 control-plane/api/assemble_main.py
# writes main.py (~51KB) with Tier 1–3 features
```

Do not run the old short `main.py` alone. Always assemble first (or rely on `./start.sh`).
