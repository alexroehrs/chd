#!/usr/bin/env bash
# Stops the local validators started by start.sh.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for f in "$HERE"/data/node*/besu.pid; do
  [ -f "$f" ] || continue
  kill "$(cat "$f")" 2>/dev/null && echo "stopped pid $(cat "$f")"
  rm -f "$f"
done
