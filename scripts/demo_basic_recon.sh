#!/usr/bin/env bash
set -euo pipefail
TOKEN=${ANDROID_SEC_MCP_TOKEN:?export ANDROID_SEC_MCP_TOKEN from /data/adb/android-sec-mcp/config.json}
URL=${ANDROID_SEC_MCP_URL:-http://127.0.0.1:8765/mcp}
curl -sS "$URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"case.run_basic_recon","arguments":{"packageName":"com.example.app"}}}' | python3 -m json.tool
