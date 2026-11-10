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

For a local Termux/Linux agent, avoid copying secrets from terminal output by writing a protected environment file directly:

```sh
python3 scripts/enroll_agent.py \
  --asset-id android-termux-controller \
  --tenant-id customer-a \
  --env-file "$HOME/.config/cyberguardian/agent.env"
```

For a remote agent, supply its HTTPS controller URL with `--api-url https://controller.example.com`. Non-loopback HTTP URLs are rejected. The generated environment file is mode 0600 and its parent directory must be private (0700).

The script stores the agent's API key, identity secret, command-signing secret, tenant and active status in:

```text
$CG_DATA_DIR/agent_credentials.json
```

The file is written atomically with mode 0600. The script prints the agent environment values once. Transfer them to the device through your approved secret-delivery process.

## 3. Configure the agent

Create a protected environment file on the enrolled Linux device, for example:

```sh
sudo install -d -m 0700 /etc/cyberguardian
sudo install -m 0600 /dev/null /etc/cyberguardian/agent.env
sudoedit /etc/cyberguardian/agent.env
```

Set the controller URL and all values printed by the enrollment script:

- `CYBERGUARDIAN_API` (or `CG_CONTROLLER_URL`)
- `CYBERGUARDIAN_API_KEY`
- `CYBERGUARDIAN_ASSET_ID`
- `CYBERGUARDIAN_TENANT`
- `CG_AGENT_IDENTITY_SECRET`
- `CG_COMMAND_SIGNING_SECRET`
- `CG_REQUIRE_AGENT_IDENTITY=1`
- `CG_REQUIRE_COMMAND_SIG=1`

Do not reuse an agent's secrets on another asset. Keep the environment file readable only by the agent service account.

### Running the enrolled agent on the controller device

If the controller and agent run on the same Linux/Termux device, configure startup to use the enrolled environment file:

```sh
chmod 600 /path/to/agent.env
export CG_AGENT_ENV_FILE=/path/to/agent.env
export CG_PRODUCTION=1
export CG_REQUIRE_AGENT_IDENTITY=1
./start.sh
```

When production identity enforcement is enabled, `start.sh` will not fall back to the shared bootstrap agent key. It starts the local agent only when `CG_AGENT_ENV_FILE` points to a regular file with no group/other permissions and the required per-agent secrets are present. Without that file, the controller services can start, but the local agent is deliberately skipped. For a non-production lab only, the legacy bootstrap agent remains available.

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
