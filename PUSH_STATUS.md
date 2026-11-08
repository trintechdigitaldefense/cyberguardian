# CyberGuardian R2 push and verification status

**Branch:** `r2-1.6.0-security`  
**Status updated:** 2026-11-08  
**Latest code commit at this status update:** `e5a25badbd95390084657605c39efc0b791dc75b`

## Confirmed present on GitHub

The following implementation files are tracked on this branch (this corrects the older status note that incorrectly described them as local-only):

- `agents/linux-ebpf/agent.py`
- `agents/linux-ebpf/containment.py`
- `agents/linux-ebpf/offline_queue.py`
- `agents/linux-ebpf/command_crypto.py`
- `control-plane/api/agent_identity.py`
- `control-plane/decision-service/main.py`
- `dashboard/main.py`
- `start.sh`, `status.sh`, `stop.sh`
- `scripts/setup_credentials.sh`

These files being present does **not** mean their security acceptance criteria have passed. See `docs/ROADMAP.md`.

## Gateway packaging repair

- Canonical source is `control-plane/api/gateway_z/00.txt` through `05.txt`.
- R2's `05.txt` differed from the verified `main` branch version and caused a truncated zlib stream. It has been restored from `main`.
- `assemble_main.py` now assembles only the six canonical gateway_z chunks, validates chunk names/count, strict base64 decoding, zlib decompression, UTF-8, source marker, Python AST, published SHA-256, and expected size.
- Published gateway digest: `39b8c5d94577bf8f317a485bf9a9ec84955249757b94395a1bc7ab3570dc0674`.
- Expected source size: `53731` bytes.
- The `gateway_hex` directory is incomplete/stale and is not used by the release assembler.
- Dockerfile runs assembly during image build.

## CI changes

- CI dependency installation is now fail-closed (no ignored pip install failures).
- Python 3.10, 3.11, and 3.12 jobs assemble and verify the gateway, run pytest, and compile the application modules.
- Docker job builds the API image and checks the container's `/health` endpoint.

Latest run: [GitHub Actions run 42510388349](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42510388349)  
Run was still in progress when this status was written. Do not mark R0 complete until every required job is green, including the Docker health smoke.

## Current automated test inventory

- `tests/test_command_crypto.py`
- `tests/test_gateway_assembly.py`

This is an initial regression suite, not complete coverage of the platform. Add targeted tests as R1-R4 are implemented.

## Remaining R0 exit criteria

1. Latest CI run is green on the exact branch head.
2. Docker image builds and its container returns HTTP 200 from `/health`.
3. Fresh clone can assemble the gateway with the published digest.
4. Pytest and compile checks pass on all supported Python versions.
5. The roadmap and changelog reflect the verified commit and results.

The older local-tree instructions and the obsolete `gateway_hex` digest have been removed from this status file.
