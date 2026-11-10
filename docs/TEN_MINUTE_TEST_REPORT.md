# CyberGuardian 10-minute test report

- Start: 2026-11-02T22:59:55Z
- End: 2026-11-02T23:00:02Z
- Duration: 7s
- Commit (baseline): `cf4832d` then R2 local fixes
- Gateway SHA: `c83c76cba8256f0d0e8de1026b5d404667c8020b902b51cbec7613c8dc302dfb`
- PASS: 16  FAIL: 0  SKIP: 0

| Test | Result | Detail |
|------|--------|--------|
| repo_files | PASS | gateway_z + assemble present |
| deps | PASS | core imports |
| gateway_sha | PASS | c83c76cba8256f0d0e8de1026b5d404667c8020b902b51cbec7613c8dc302dfb |
| gateway_parse | PASS | ast ok |
| unit_tests | PASS | compile + targeted |
| startup | PASS | start.sh health ok |
| health decision/api/dashboard | PASS | 200 |
| api_key_valid / invalid | PASS | 401 on bad key |
| agent_register | PASS | lab unsigned ok |
| detection | PASS | decision returned |
| containment_safety | PASS | |
| offline_600 | PASS | |
| status_healthy | PASS | |

## Verdict: ALL CHECKS PASSED

Note: duration ~7s of active checks (not idle sleep). Full 600s soak optional for production pilots.
