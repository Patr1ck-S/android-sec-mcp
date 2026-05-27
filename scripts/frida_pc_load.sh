#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  ANDROID_SEC_MCP_TOKEN=... scripts/frida_pc_load.sh spawn  <package.name> hook.js
  ANDROID_SEC_MCP_TOKEN=... scripts/frida_pc_load.sh attach <package.name> hook.js
  ANDROID_SEC_MCP_TOKEN=... scripts/frida_pc_load.sh spawn  <package.name> --auto-debug
  ANDROID_SEC_MCP_TOKEN=... scripts/frida_pc_load.sh attach <package.name> --auto-debug

env:
  ANDROID_SEC_MCP_URL     default: http://127.0.0.1:8765/mcp
  FRIDA_PC_WAIT           default: 10
  FRIDA_HOST              optional: use -H host instead of -U, e.g. 127.0.0.1:27042
  FRIDA_LOCAL_DIR         default: build/frida-pc
EOF
  exit 2
}

if [ $# -lt 3 ]; then
  usage
fi

MODE=$1
PACKAGE=$2
SCRIPT_FILE=$3
AUTO_DEBUG=0
TOKEN=${ANDROID_SEC_MCP_TOKEN:?export ANDROID_SEC_MCP_TOKEN}
URL=${ANDROID_SEC_MCP_URL:-http://127.0.0.1:8765/mcp}
WAIT=${FRIDA_PC_WAIT:-10}
LOCAL_ROOT=${FRIDA_LOCAL_DIR:-build/frida-pc}

case "$MODE" in
  spawn|attach) ;;
  *) echo "mode must be spawn or attach" >&2; exit 2 ;;
esac

if [ "$SCRIPT_FILE" = "--auto-debug" ]; then
  AUTO_DEBUG=1
elif [ ! -f "$SCRIPT_FILE" ]; then
  echo "script file not found: $SCRIPT_FILE" >&2
  exit 2
fi

mkdir -p "$LOCAL_ROOT/$PACKAGE"

mcp_call() {
  local tool=$1
  local args_json=$2
  python3 - "$tool" "$args_json" <<'PY' | curl -sS "$URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d @-
import json, sys
tool = sys.argv[1]
args = json.loads(sys.argv[2])
print(json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": tool, "arguments": args},
}))
PY
}

if [ "$AUTO_DEBUG" = "1" ]; then
  PREP_TOOL=ctf.prepare_debugger_bypass
  PREP_ARGS=$(PACKAGE="$PACKAGE" python3 - <<'PY'
import json, os
print(json.dumps({
    "packageName": os.environ["PACKAGE"],
    "confirm": True,
}))
PY
)
  echo "[*] Scanning debugger detection and preparing anti-debug script through MCP..."
else
  PREP_TOOL=frida.prepare_pc_script
  PREP_ARGS=$(PACKAGE="$PACKAGE" SCRIPT_FILE="$SCRIPT_FILE" python3 - <<'PY'
import json, os, pathlib
script_path = pathlib.Path(os.environ["SCRIPT_FILE"])
print(json.dumps({
    "packageName": os.environ["PACKAGE"],
    "script": script_path.read_text(),
    "prefix": script_path.stem,
}))
PY
)
  echo "[*] Preparing script on Android through MCP..."
fi

PREP_RESP=$(mcp_call "$PREP_TOOL" "$PREP_ARGS")

eval "$(PREP_RESP="$PREP_RESP" LOCAL_ROOT="$LOCAL_ROOT" PACKAGE="$PACKAGE" python3 - <<'PY'
import json, os, shlex
j = json.loads(os.environ["PREP_RESP"])
if "error" in j:
    raise SystemExit("MCP error: " + json.dumps(j["error"], ensure_ascii=False))
sc = j["result"]["structuredContent"]
sess = sc["session"]
pc = sess.get("pcMode") or sc.get("pcMode") or {}
session_id = sess["id"]
device_path = pc.get("scriptPathOnDevice") or sc.get("scriptPath")
save_as = pc.get("saveAs") or "hook.js"
local_path = os.path.join(os.environ["LOCAL_ROOT"], os.environ["PACKAGE"], session_id + "-" + save_as)
print("SESSION_ID=" + shlex.quote(session_id))
print("DEVICE_SCRIPT=" + shlex.quote(device_path))
print("LOCAL_SCRIPT=" + shlex.quote(local_path))
PY
)"

echo "[*] Session: $SESSION_ID"
echo "[*] Device script: $DEVICE_SCRIPT"
echo "[*] Pulling generated JS to: $LOCAL_SCRIPT"
adb exec-out su -c "cat '$DEVICE_SCRIPT'" > "$LOCAL_SCRIPT"

echo "[*] Ensuring frida-server is running through MCP..."
START_RESP=$(mcp_call frida.server_start '{"confirm":true}' || true)
echo "$START_RESP" > "$LOCAL_ROOT/$PACKAGE/$SESSION_ID-server_start.json"

FRIDA_ARGS=()
if [ -n "${FRIDA_HOST:-}" ]; then
  FRIDA_ARGS=(-H "$FRIDA_HOST")
  if [[ "$FRIDA_HOST" == 127.0.0.1:* || "$FRIDA_HOST" == localhost:* ]]; then
    adb forward tcp:${FRIDA_HOST##*:} tcp:${FRIDA_HOST##*:} >/dev/null
  fi
else
  FRIDA_ARGS=(-U)
fi

if [ "$MODE" = "spawn" ]; then
  CMD=(frida "${FRIDA_ARGS[@]}" -f "$PACKAGE" -l "$LOCAL_SCRIPT" -q -t "$WAIT")
else
  CMD=(frida "${FRIDA_ARGS[@]}" -n "$PACKAGE" -l "$LOCAL_SCRIPT" -q -t "$WAIT")
fi

LOG="$LOCAL_ROOT/$PACKAGE/$SESSION_ID-$MODE.log"
echo "[*] Running: ${CMD[*]}"
set +e
"${CMD[@]}" >"$LOG" 2>&1
EXIT_CODE=$?
set -e

echo "[*] Frida exit code: $EXIT_CODE"
echo "[*] Frida log: $LOG"

INGEST_ARGS=$(SESSION_ID="$SESSION_ID" MODE="$MODE" EXIT_CODE="$EXIT_CODE" LOG="$LOG" CMD_STR="${CMD[*]}" python3 - <<'PY'
import json, os, pathlib
print(json.dumps({
    "sessionId": os.environ["SESSION_ID"],
    "mode": os.environ["MODE"],
    "exitCode": int(os.environ["EXIT_CODE"]),
    "command": os.environ["CMD_STR"],
    "output": pathlib.Path(os.environ["LOG"]).read_text(errors="replace"),
}))
PY
)

echo "[*] Sending Frida result back to MCP..."
mcp_call frida.ingest_pc_result "$INGEST_ARGS" | python3 -m json.tool

echo "[*] Collecting MCP session messages..."
mcp_call frida.collect_messages "{\"sessionId\":\"$SESSION_ID\",\"limit\":200}" | python3 -m json.tool
