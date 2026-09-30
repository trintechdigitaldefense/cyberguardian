# CyberGuardian Architecture

## Components

1. **Linux Agent** — periodic process/FIM/baseline scans; POSTs detections; disk-backed offline queue.
2. **API Gateway** — multi-tenant SQLite store; dual API keys; gate; issues; fleet; inventory; reports.
3. **Decision Service** — severity/confidence → actions; playbooks; protection mode.
4. **NAD / TIE / Compliance** — optional enrichment and scoring stubs for pilot.
5. **Dashboard** — authenticated operator UI.

## Data flow

```
Agent --(API key agent)--> API /v1/detections
                              |
                              v
                        Decision /v1/decide
                              |
              +---------------+---------------+
              | Client Mode ON                | Client Mode OFF
              v                               v
        pending_actions (gate)         known-playbook execute
              |                               |
              v                               v
        human approve/reject            issue_memory auto_fixed
```

## Auth

- `api_key` — admin (backup, gate approve, client-mode, email)
- `agent_api_key` — register, detections, issue remember only
