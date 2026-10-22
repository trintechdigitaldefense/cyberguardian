# CyberGuardian — one-page Rules of Engagement (pilot)

Authorized defensive use only · TrinTech Digital Defense

## Default posture

1. **Client Mode ON** for all production / client-tagged hosts.
2. Control plane **not** on the public internet (`CG_HARDENED=1` or VPN/SSH tunnel).
3. Agent uses **agent key** only; admin key stays with operators.
4. Auto-remediate only on assets tagged `lab` / `dev` / `staging` when Client Mode is OFF.
5. Production tags (`prod`, `client`, `critical`) are **never** auto-isolated without human approve.

## Allowed during pilot

- Process kill after human approve
- Host network isolate / IP block after human approve
- FIM and outbound alerts
- Mark benign (14-day suppress) for known false positives
- Undo isolate (rollback) when containment was confirmed unnecessary

## Not in scope

- Fully autonomous isolate on production without approve
- Windows / macOS agents
- Replacing backups, identity, or patching programs

## Sign-off

Client: ________________  Date: ________  
Operator: ______________  Date: ________
