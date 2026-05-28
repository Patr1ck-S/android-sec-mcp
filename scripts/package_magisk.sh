#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT/magisk"
OUT="$ROOT/build/android-sec-mcp-magisk.zip"
mkdir -p "$ROOT/build"
rm -f "$OUT"
zip -r -X "$OUT" META-INF customize.sh module.prop service.sh uninstall.sh system bypass-profiles -x "system/bin/.gitkeep" >/dev/null
echo "$OUT"
