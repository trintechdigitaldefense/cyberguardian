# Code review fix plan (Nov 2026)

External review: promising supervised EDR foundation; not production-ready until reliability/security of existing features is proven.

## P0 — release blocking

1. **API gateway packaging** — full source must be in repo; clean clone must import without tarballs.
   - Plain `main_part0.py.txt` … `main_part2.py.txt` + fail-loud `assemble_main.py` + bootstrap `main.py`.
   - Prefer also committing assembled `main_full.py` or single `main.py` (~52KB) from build machine:
     ```bash
     git add control-plane/api/main.py control-plane/api/main_part*.py.txt
     git commit -m "P0: full API gateway source"
     git push origin main
     ```
   - Remove obsolete `gateway_parts/*.z64` and `main_b64/` once parts are live.

2. **start.sh honesty** — do not swallow assemble failures; wait for HTTP health; add `status.sh`.

3. **Containment safety** — PID+starttime identity; IP validation; dedicated chains; atomic isolate/restore; verified rollback.

4. **Approval end-to-end** — single enforcement point at gateway; single-use signed command IDs; no auto_approved bypass of Client Mode.

5. **Agent identity** — fail closed when secret set; admin keys never on endpoints.

## P1 — dashboard / agent hardening

- Persistent sessions, Secure cookies, Argon2id passwords, operator identity on audit.
- FIM baseline approval; SHA-256 authwatch; bounded offline queue; dedicated heartbeat.

## Acceptance for pilot sale

- Clean clone starts API + dashboard.
- One host: Client Mode ON → detect → approve → contain → audit → weekly PDF.
- Containment VM tests: isolate, restore, bad PID, missing nft/iptables.
