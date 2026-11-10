#!/usr/bin/env python3
"""Export the audit checkpoint HMAC key to a private recovery file without printing it."""
from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Private recovery-key file destination")
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("CG_DATA_DIR", str(ROOT / "data")),
        help="Controller data directory containing credentials.json",
    )
    parser.add_argument("--force", action="store_true", help="Atomically replace an existing output file")
    args = parser.parse_args()

    data_dir = Path(args.data_dir).expanduser()
    if not data_dir.is_absolute():
        data_dir = ROOT / data_dir
    credentials_path = data_dir / "credentials.json"
    if data_dir.is_symlink() or credentials_path.is_symlink():
        parser.error("credential directory and file must not be symlinks")
    try:
        if stat.S_IMODE(data_dir.stat().st_mode) & 0o077:
            parser.error("controller data directory must be private (0700)")
        if stat.S_IMODE(credentials_path.stat().st_mode) & 0o077:
            parser.error("credentials.json must be private (0600)")
        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(f"cannot read protected credentials: {exc}")
    if not isinstance(credentials, dict):
        parser.error("credentials.json has an invalid schema")

    key_hex = str(credentials.get("audit_checkpoint_key_hex") or "").strip()
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        parser.error("audit checkpoint key is not valid hexadecimal")
    if len(key) < 32:
        parser.error("audit checkpoint key must contain at least 32 random bytes")

    output = Path(args.out).expanduser()
    if output.parent.is_symlink() or output.is_symlink():
        parser.error("recovery output directory and file must not be symlinks")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if stat.S_IMODE(output.parent.stat().st_mode) & 0o077:
        parser.error("recovery output directory must be private (0700)")
    if output.exists() and not args.force:
        parser.error("output already exists; use --force to replace it")

    fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(key_hex + "\\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, output)
        os.chmod(output, 0o600)
        dir_fd = os.open(str(output.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass

    print(f"Audit checkpoint recovery key written to {output}; secret value was not displayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
