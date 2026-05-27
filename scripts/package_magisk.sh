#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT/magisk"
OUT="$ROOT/build/android-sec-mcp-magisk.zip"
mkdir -p "$ROOT/build"
rm -f "$OUT"
zip -r "$OUT" module.prop service.sh uninstall.sh system bypass-profiles >/dev/null
echo "$OUT"
