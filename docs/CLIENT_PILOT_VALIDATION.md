# CyberGuardian R4 — Owner Pilot Validation Pack

**Status:** TEST CANDIDATE — NOT PRODUCTION APPROVED  
**Branch:** `r4-operational-drill-runbooks`  
**Purpose:** Let TrinTech Digital Defense perform a controlled clone, install, dashboard, reporting and safe-workflow validation before any client deployment.

This guide is an owner-operated lab procedure. Use synthetic data and devices you control. Do not connect this candidate to a client network, install it on client endpoints, or approve disruptive actions during this test.

## 1. What this candidate is ready to test

- Fresh-clone installation and standalone service startup.
- Local API, decision-service and dashboard health.
- Dashboard login and operator workflows.
- Client Mode default and human approval gate.
- Synthetic detections/issues and audit visibility.
- Historical audit query and date-range PDF reporting.
- Agent enrollment, heartbeat and basic fleet visibility on a controlled Linux/Ubuntu host.
- Safe shutdown, restart and log review.

## 2. What is not yet certified

The following are release blockers, not optional paperwork:

1. Physical offline-queue test: disconnect the agent's actual network path, generate synthetic events, restart the agent while disconnected, reconnect, and prove acknowledged delivery without loss/duplication beyond documented at-least-once transport.
2. Physical multi-agent test: use at least two independently enrolled devices and demonstrate online → offline → online, revocation, fresh re-enrollment and tenant separation.
3. Independent recovery: export a signed audit checkpoint, transfer it to storage under a separate administrative boundary, verify it there, restore it to a separately provisioned clean host, then append a new event and re-verify the chain.
4. Client retention approval: obtain the client's completed and signed `docs/R4_RETENTION_APPROVAL.md`. Do not invent retention periods or enable irreversible purge.
5. Exact-head R4 acceptance review and authorized sign-off.

Passing the owner lab checklist does not pass these gates and does not authorize production deployment.

## 3. Android Termux / Ubuntu preparation

Run CyberGuardian inside the Ubuntu environment, not directly in the Termux base shell. The standalone launcher requires Linux process management and standard Linux utilities. Android/Termux kernel, filesystem and firewall behaviour still need separate validation.

Inside Ubuntu, install the basics:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip curl openssl
```

If your Ubuntu image lacks compiler/runtime packages required by Python wheels, install its standard build tools before installing requirements. Do not attempt firewall/containment testing on the Android host during this first pass.

## 4. Clone the exact R4 candidate

```bash
git clone --branch r4-operational-drill-runbooks --single-branch \
  https://github.com/trintechdigitaldefense/cyberguardian.git
cd cyberguardian
git status --short --branch
git rev-parse HEAD
```

Record the full output of `git rev-parse HEAD` in your test notes. Confirm the branch is `r4-operational-drill-runbooks` and the working tree is clean.

## 5. Install dependencies and create credentials

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
bash scripts/setup_credentials.sh
```

Use a unique lab administrator password. Keep the generated `data/credentials.json` private; do not upload it, screenshot it, paste it into chat, or commit it. The credential setup creates secrets used by the local services and audit checkpoint workflow.

Check that Git is not tracking the local data directory:

```bash
git status --short
```

If credentials or other secrets appear as untracked files, do not add them to Git. Stop and review `.gitignore` before proceeding.

## 6. Start safely for the first dashboard test

Start without automatically launching an agent. The services should bind to loopback only:

```bash
export CG_HARDENED=1
export CG_DISABLE_LOCAL_AGENT=1
./start.sh
```

Expected local URLs:

- Dashboard: `http://127.0.0.1:3000`
- API health: `http://127.0.0.1:8080/health`
- Decision service health: `http://127.0.0.1:8001/health`

In another Ubuntu shell:

```bash
bash scripts/client_health.sh
bash status.sh
```

Log in to the dashboard with the credentials you created. Confirm Client Mode is ON before submitting any synthetic event. Keep the dashboard local; do not expose these ports to the internet or a client LAN.

If a service fails to start, stop here and inspect `/tmp/cg-decision.log`, `/tmp/cg-api.log`, `/tmp/cg-dashboard.log` and `/tmp/cg-nad.log`. Do not work around a failed security check by weakening production settings.

## 7. Safe synthetic workflow

Run the repository's pilot dry-run only after the dashboard and API health checks pass:

```bash
bash scripts/dry_run_pilot.sh
```

Expected behaviour:
- API health is successful.
- Client Mode is set to true.
- A synthetic, clearly labelled dry-run issue is created.
- Auto-remediation remains blocked while Client Mode is ON / without the required human approval.

Do not approve a kill, isolate or block action on your Android device or any real client asset. If a dashboard action would execute on a real host, reject it or leave it pending.

Inspect the dashboard's issue, gate and audit views. Confirm the test event is visibly synthetic and belongs to the lab tenant.

## 8. Historical PDF reporting check

Use the dashboard's client reporting area to select a bounded reporting period that includes the synthetic event. Generate the PDF and verify:

- Tenant identity is the lab tenant.
- Reporting period and UTC boundaries are shown.
- Historical activity contains only records inside the selected period.
- Source event IDs and record hashes are present.
- The audit checkpoint head is present.
- Current fleet/risk/gate/issue figures are labelled as a current snapshot, not as historical metrics.
- A period with no matching audit records is not silently filled with current-state data.

Retain the PDF only as synthetic lab evidence. Do not include passwords, API keys, HMAC keys or personal/client data in the report or test notes.

## 9. Agent and second-device tests

Only after the single-host dashboard test is clean, enroll a disposable lab asset using the documented per-agent enrollment process in `docs/AGENT_ENROLLMENT.md`. Use a unique asset ID and tenant such as `trintech-lab`. Never reuse the controller administrator key as an agent key.

For the physical two-agent exercise, prepare a second independently controlled Linux/Ubuntu device. Follow `docs/R4_OPERATIONAL_DRILL_RUNBOOKS.md` section 4 exactly. A second process on the same phone is not a substitute for a second physical device/network path.

## 10. Stop and preserve evidence

Stop the services cleanly:

```bash
./stop.sh
```

Record:
- Exact Git commit SHA and branch.
- Android model, Android version, Termux version, Ubuntu/proot environment and kernel details.
- Python version and dependency installation result.
- Service health results and any startup errors.
- Whether dashboard login, Client Mode, synthetic workflow and PDF report passed.
- Redacted logs and screenshots; never include secret values.
- Failures, unexpected behaviour and the exact steps to reproduce them.

## 11. R4 exit decision

Mark each item as PASS only when its evidence exists. The owner lab checks above are useful pre-release validation; physical recovery, physical multi-agent/offline exercises and client retention approval remain separate mandatory gates.

**Release status remains NOT CLIENT-READY until the complete R4 acceptance matrix is signed off.** Keep the PR draft and R5 locked until then.
