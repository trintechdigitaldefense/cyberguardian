# Push status — full gateway

## On GitHub (partial)

- Bootstrap `main.py`, `assemble_main.py`, `decode_gateway_b64.py`
- Some `gateway_b64/p*.b64` fragments (incomplete set — do not rely on decode until all 24 parts are present)
- `gw_src_00.txt`, `gw_src_13.txt` (incomplete plain set)

## Close the gap (build machine — required)

From the tree that has `control-plane/api/main_full.py` (~54KB) and all fragments:

```bash
cd /path/to/CyberGuardian

# Verify
python3 control-plane/api/assemble_main.py
sha256sum control-plane/api/main_full.py
# expect: 39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674

git add control-plane/api/main_full.py \
        control-plane/api/main.py \
        control-plane/api/assemble_main.py \
        control-plane/api/decode_gateway_b64.py \
        control-plane/api/gateway_b64 \
        control-plane/api/gw_src_*.txt \
        control-plane/api/GATEWAY_SHA256.txt \
        control-plane/api/agent_identity.py \
        start.sh status.sh \
        agents/linux-ebpf/containment.py \
        dashboard/main.py \
        scripts/

git commit -m "P0: full API gateway main_full.py + fragments + P0/P1 hardening"
git push origin main

git rm -rf control-plane/api/gateway_parts control-plane/api/main_b64 2>/dev/null || true
git commit -m "P0: remove obsolete zlib fragments" || true
git push origin main
```

Tarball on build host: `cyberguardian-p0-gateway-src.tgz`

## Acceptance

```bash
git clone https://github.com/trintechdigitaldefense/cyberguardian.git
cd cyberguardian
python3 control-plane/api/assemble_main.py
bash start.sh
curl -sS http://127.0.0.1:8080/health
```
