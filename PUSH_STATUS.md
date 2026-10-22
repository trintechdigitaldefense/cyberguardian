# Push status — CyberGuardian 1.4.0-tier3

**Date:** 2026-10-22

## Dashboard wiring — complete

All operator UI actions proxy to the API:

- Client Mode, Gate approve/reject, Mark benign, Undo isolate
- Audit, Scorecard, Weekly digest, Fleet, Inventory, Hardening

## Gateway source

Full API is `control-plane/api/main.py.part1` + `main.py.part2`.
`./start.sh` runs `assemble_main.py` before starting uvicorn.

Local workspace also keeps a complete `main.py` for development.

## On main branch

Dashboard HTML + main.py ops, containment, allowlist, identity, sentinel,
fp_feedback, HARDENING.md, pilot scripts, VERSION 1.4.0-tier3.
