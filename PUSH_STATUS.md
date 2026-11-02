# Push status — full gateway (compressed)

## On GitHub (complete path)

- `control-plane/api/gateway_z/00.txt` … `05.txt` — zlib+base64 of full `main_full.py`
- `control-plane/api/decode_gateway_z.py`
- `control-plane/api/assemble_main.py` (prefers gateway_z)
- Expected SHA256: `39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674`
- Size: 53731 bytes

## Clean clone

```bash
git clone https://github.com/trintechdigitaldefense/cyberguardian.git
cd cyberguardian
python3 control-plane/api/assemble_main.py
# or: python3 control-plane/api/decode_gateway_z.py
sha256sum control-plane/api/main_full.py
bash start.sh
curl -sS http://127.0.0.1:8080/health
```

## Integrity

Six parts, tightly packed (~15KB total vs 54KB plain). Round-trip verified before push.
