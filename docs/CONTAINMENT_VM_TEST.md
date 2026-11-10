# CyberGuardian containment integration test (disposable VM only)

This is a privileged integration test for R2. It creates real firewall rules, so it must **never** be run on a client, production host, or a normal workstation network namespace.

## Preconditions

- A disposable Linux VM that can be discarded after testing.
- Root/sudo access.
- util-linux `unshare`.
- Either nftables (`nft`) or both `iptables` and `ip6tables`.
- Python dependencies needed by the CyberGuardian agent module.

## Run

From the repository root:

```bash
sudo python3 scripts/test_containment_namespace.py
```

The harness first records the caller's network namespace, then starts a child process in a separate network namespace. It refuses to proceed if the namespace identity did not change. Firewall mutations are confined to that disposable namespace, and the namespace is destroyed when the process exits.

## Checks performed

1. Add and verify an IPv4 block.
2. Add and verify an IPv6 block.
3. Apply host-output isolation with both IPv4 and IPv6 controller recovery addresses.
4. Verify the controller allow rules and final drop rule in the selected backend.
5. Run `restore_network()`.
6. Verify the CyberGuardian-owned firewall objects and state markers are removed.

## Evidence to retain

Record the exact Git commit SHA, Linux distribution/kernel version, backend used, command output, start/end timestamps, and whether every check passed. If `unshare` is unavailable or denied, do not remove the namespace guard or run the script directly against the host firewall; use another disposable VM with the required privileges.

This harness is a necessary R2 integration check, not the R5 600-second stability test and not a production certification.
