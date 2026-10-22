# API gateway layout (v1.5.1+)

`main.py` is a thin loader. Full source is split for GitHub:

- `gateway_parts/part0.py`
- `gateway_parts/part1.py`
- `gateway_parts/part2.py`

On first import / uvicorn start, parts are joined into `_gateway_assembled.py` and loaded as `app`.

Local development may also keep a monolithic `main.py` — the loader is what Git clones use.

```bash
# verify after clone
cd control-plane/api && python3 -c "from main import app; print(app.title)"
```
