# Changelog

## 1.6.0-security — 2026-11-10

### Release hardening and R4 reliability work

- R0-R3 engineering gates completed on the isolated `r2-1.6.0-security` branch; see `docs/ROADMAP.md` for exact CI evidence.
- Dashboard operator assertions, service-level credentials/scopes, tenant-bound gateway authorization, audit attribution, secure browser policy, and production Compose acceptance.
- Offline agent queue now uses locked, atomic, fsynced JSONL writes, bounded record/byte capacity, duplicate suppression, acknowledgement-only removal, retry backoff, bounded flush batches, and explicit overflow status.
- Added CI tests for concurrent queue writers, retry/acknowledgement behavior, overflow preservation, permissions and corrupt-record retention.
- Gateway audit writes now append to a separate hash-chained JSONL ledger; added chain verification and consistent verified snapshot export commands.
- Issue-memory updates now use process locking and atomic fsync/replace, enforce owner-only file permissions and fail closed on malformed records.
- Tenant-scoped fleet dashboard responses project stale agents to offline and unknown timestamps to unknown while preserving revoked/disabled states.
- Weekly client report generation requires an explicit tenant, validates scorecard tenant identity, aborts on missing source data, and supports atomic formula-safe CSV scorecard export.

**Status:** R4 remains in progress; queue, audit-chain/export, issue persistence, fleet staleness and tenant-scoped report code gates are covered by CI (101 tests on commit `dfd87f73943c8dc1388ec1ebfd3a9309b2132f04`). Full restart/recovery, heartbeat/revocation transitions and end-to-end workflow acceptance remain open. This branch is not a client-ready release. R5's real 600-second soak and supervised pilot acceptance have not been completed.



## 1.2.0-tier1 — 2026-10-22

### Tier 1 — real containment + operator quality

- **Real host containment** — approved isolate / kill / block are queued to the Linux agent and executed on the endpoint (`containment.py`: SIGTERM/SIGKILL, nft/iptables block & soft isolate)
- **Agent command channel** — `GET /v1/agent/commands`, `POST /v1/agent/command-result`; agent polls every scan cycle
- **Action audit trail** — staged → approved/rejected → delivered → executed/failed; dashboard Audit panel
- **Playbook evidence** — decision service returns matched tags/title terms + summary; gate UI shows “Why”
- **Pilot scorecard** — `GET /v1/pilot/scorecard` + dashboard panel (Client Mode, agent online, audit path)
- **Weekly operator digest** — `GET /v1/reports/weekly` + `scripts/weekly_digest.sh`
- **One-click pilot pack** — `scripts/pilot_day1.sh` (creds → start → Client Mode ON → health → dry-run → scorecard)

### Safety notes

- Client Mode remains default ON
- Network isolate/block require root on the agent host; without root the agent logs intent and reports honestly
- Kill refuses PID 1 and the agent’s own process

---

## 1.1.0-pilot — 2026-09-30

### Production pilot release

- **Dual API keys** — admin vs agent least-privilege
- **Client Mode (default ON)** — isolate / kill / block staged for human approval
- **Issue memory** — persistent JSONL fingerprints; known-playbook auto-remediate only when Client Mode OFF
- **Offline queue** — agent disk JSONL when controller unreachable; flush on reconnect
- **Fleet + inventory** — registered assets, last-seen, best-effort LAN discovery
- **Human gate** — pending_actions table, approve/reject endpoints
- **Dashboard** — login, client-mode panel, remembered issues, fleet view
- **Scripts** — setup_credentials, dry_run_pilot, client_health, start/stop
- **Docs** — PILOT_SCOPE.md honesty scope, ARCHITECTURE.md
- Fixed issue_memory store path (repo-root `data/`)

### Scope honesty

Not a 24/7 SOC, not full Windows/macOS EDR, not open-ended autonomous AI.
Auto-remediate uses **known playbooks only**.
