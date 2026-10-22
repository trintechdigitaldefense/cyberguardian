#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="$ROOT/data/cyberguardian.db"
OUT="$ROOT/data/backups"
mkdir -p "$OUT"
if [ ! -f "$DB" ]; then
  echo "No database yet at $DB"
  exit 0
fi
STAMP=$(date +%Y%m%d-%H%M%S)
if command -v sqlite3 >/dev/null 2>&1; then
  sqlite3 "$DB" ".backup '$OUT/cyberguardian-$STAMP.db'"
else
  cp -a "$DB" "$OUT/cyberguardian-$STAMP.db"
fi
ls -1t "$OUT"/cyberguardian-*.db 2>/dev/null | tail -n +15 | xargs -r rm -f
echo "Backup: $OUT/cyberguardian-$STAMP.db"
