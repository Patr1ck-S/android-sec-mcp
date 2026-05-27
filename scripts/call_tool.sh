#!/usr/bin/env bash
set -euo pipefail
if [ $# -lt 1 ]; then
  echo "usage: ANDROID_SEC_MCP_TOKEN=... $0 tool.name '{\"arg\":true}'" >&2
  exit 2
fi
TOKEN=${ANDROID_SEC_MCP_TOKEN:?export ANDROID_SEC_MCP_TOKEN}
URL=${ANDROID_SEC_MCP_URL:-http://127.0.0.1:8765/mcp}
TOOL=$1
ARGS=${2:-{}}
curl -sS "$URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":$ARGS}}" | python3 -m json.tool
