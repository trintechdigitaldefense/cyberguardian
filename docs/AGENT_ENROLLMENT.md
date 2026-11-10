# CyberGuardian per-agent enrollment and command signing

This procedure provisions one dedicated API key, identity HMAC secret, and command-signing HMAC secret per enrolled asset. Run enrollment only on the controller host. Never commit the generated credentials or paste them into source control, tickets, or chat.

## 1. Prepare the controller

Set these environment variables in the controller service environment:

```sh
CG_PRODUCTION=1
CG_REQUIRE_AGENT_IDENTITY=1
CG_DATA_HOST_DIR=/var/lib/cyberguardian

# When running the enrollment script directly on the controller host:
CG_DATA_DIR=/var/lib/cyberguardian
```

Use a persistent, access-controlled data directory. Create it with mode 0700 and ensure the controller service account owns it. With Docker Compose, set CG_DATA_HOST_DIR to this host path; Compose mounts it at /app/data and sets CG_DATA_DIR=/app/data inside the API container. When running the enrollment script on the host, set CG_DATA_DIR to the host path. Keep the admin API key separate from every agent key.

Restart the API after setting the production variables. In production, an agent without an active per-agent enrollment record is rejected.

## 2. Enroll an asset

On the controller host, run:

```sh
python3 scripts/enroll_agent.py --asset-id linux-server-01 --tenant-id customer-a
```

For a local Termux/Linux agent running on the controller device, you do not need to copy secrets into an environment file. The secure launcher reads the protected registry directly:

```sh
python3 scripts/enroll_agent.py --asset-id android-termux-controller --tenant-id customer-a
CG_AGENT_ASSET_ID=android-termux-controller CG_PRODUCTION=1 CG_REQUIRE_AGENT_IDENTITY=1 ./start.sh
```

For a remote agent, write a protected environment file on the controller and transfer it through your approved secret-delivery process:

```sh
python3 scripts/enroll_agent.py \
  --asset-id linux-server-01 \
  --tenant-id customer-a \
  --api-url https://controller.example.com \
  --env-file "$HOME/.config/cyberguardian/linux-server-01.env"
```

Non-loopback HTTP URLs are rejected. The generated environment file is mode 0600 and its parent directory must be private (0700).

The script stores the agent's API key, identity secret, command-signing secret, tenant and active status in:

```text
$CG_DATA_DIR/agent_credentials.json
```

The file is written atomically with mode 0600. The enrollment script does not print any secret values. The controller-side launcher can read the registry directly; remote agents must receive the protected environment file through your approved secret-delivery process.

## 3. Configure and start the remote agent

Install or clone the CyberGuardian agent code on the remote Linux device, then transfer the protected environment file to it through your approved secret-delivery process. Keep the file and parent directory private (0600 and 0700):

```sh
sudo install -d -m 0700 /etc/cyberguardian
sudo install -m 0600 /secure-transfer/linux-server-01.env /etc/cyberguardian/agent.env
python3 scripts/run_enrolled_agent.py --env-file /etc/cyberguardian/agent.env --interval 60
```

The launcher reads the asset, tenant and per-device credentials from that protected file, validates the required identity and command-signature settings, filters inherited server credentials from the child process environment, and refuses weak credentials or insecure file permissions. It does not require the controller's local enrollment registry to exist on the remote host.

For a local agent running on the controller device, use the registry-backed form instead:

```sh
CG_AGENT_ASSET_ID=android-termux-controller CG_PRODUCTION=1 CG_REQUIRE_AGENT_IDENTITY=1 ./start.sh
```

Do not reuse an agent's secrets on another asset. Keep the environment file readable only by the agent service account.

Registration is retried with a fresh timestamp on the next heartbeat rather than placed in the offline queue, because signed registration envelopes expire. Durable detections and command results continue to use the offline queue. Each durable POST carries a deterministic SHA-256 event ID in `X-CG-Event-ID`; the gateway records the response in the same SQLite transaction as the route's database writes, so a retry after an ambiguous acknowledgement replays the original response instead of repeating the database side effect. Idempotency records are retained for the lifetime of queued events (there is no automatic queue expiry) with a 200,000-record fail-closed capacity limit. When the limit is reached, the gateway returns 503 and agents retain queued events; operators must expand capacity or perform a reviewed cleanup only after confirming the corresponding agent queues are drained. HTTP 401/403 responses stop the agent without queueing rejected requests; rotate or re-enroll the device credentials before restarting it.

### Running the enrolled agent on the controller device

If the controller and agent run on the same Linux/Termux device, set the enrolled asset ID and start the stack:

```sh
export CG_AGENT_ASSET_ID=android-termux-controller
export CG_PRODUCTION=1
export CG_REQUIRE_AGENT_IDENTITY=1
./start.sh
```

`start.sh` invokes `scripts/run_enrolled_agent.py`, which loads the active per-device API key, identity secret, command secret and tenant from the protected controller registry without printing them. The launcher refuses revoked, unknown or incomplete records. Alternatively, `CG_AGENT_ENV_FILE` can point to a protected environment file for an enrolled local or remote agent. When production identity enforcement is enabled, `start.sh` never falls back to the shared bootstrap agent key. For a non-production lab only, the legacy bootstrap agent remains available.

## 4. Verify enrollment

- Start the agent and confirm registration succeeds.
- Confirm the asset appears under the expected tenant.
- Confirm command polling succeeds with the enrolled API key.
- Confirm an issued command has a valid signature, matching asset and tenant, an expiry, a unique nonce and (for disruptive actions) an approval reference.
- Confirm the agent rejects missing/bad signatures, expired commands, wrong-asset/tenant commands, and replayed command IDs/nonces.
- Confirm a revoked key can no longer register, poll commands or report command results.

## 5. Rotate or revoke

Rotate all three per-agent secrets:

```sh
python3 scripts/enroll_agent.py --asset-id linux-server-01 --tenant-id customer-a --rotate
```

Securely replace the values in the agent's environment file and restart that agent. The previous credentials are replaced in the controller's active record.

Revoke an asset:

```sh
python3 scripts/enroll_agent.py --asset-id linux-server-01 --revoke
```

Revocation changes the record status to revoked. The controller rejects the old API key and does not sign further commands for that asset.

## Safety notes

- Keep `$CG_DATA_DIR/agent_credentials.json` out of Git and backups that are accessible to ordinary users.
- Back up the credential store only through an encrypted, access-controlled process.
- A credential rotation should be coordinated with the device operator to avoid an unintended monitoring outage.
- Do not enable production mode until all intended agents have active per-agent records and their environment files are securely provisioned.
- Disruptive actions remain human-approved. Signing proves command authenticity and integrity; it does not replace authorization, approval, or operator review.
