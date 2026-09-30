# Changelog

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
