#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
mkdir -p build .gocache magisk/system/bin
: "${GOOS:=android}"
: "${GOARCH:=arm64}"
: "${CGO_ENABLED:=0}"
export GOOS GOARCH CGO_ENABLED GOCACHE="$ROOT/.gocache"
echo "Building android-sec-mcp for GOOS=$GOOS GOARCH=$GOARCH"
go build -trimpath -ldflags "-s -w" -o build/android-sec-mcp ./daemon
cp build/android-sec-mcp magisk/system/bin/android-sec-mcp
chmod 755 magisk/system/bin/android-sec-mcp
echo "Built: $ROOT/build/android-sec-mcp"
echo "Copied to: $ROOT/magisk/system/bin/android-sec-mcp"
