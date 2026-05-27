#!/system/bin/sh
# android-sec-mcp - Magisk late_start service
MODDIR=${0%/*}
DATA_DIR=/data/adb/android-sec-mcp
CONFIG=$DATA_DIR/config.json
WORKSPACE=/data/local/tmp/android-sec-mcp/cases
PROFILE_DIR=$DATA_DIR/bypass-profiles
DAEMON=$MODDIR/system/bin/android-sec-mcp
BUNDLED_FRIDA=$MODDIR/system/bin/frida-server
LOG=$DATA_DIR/daemon.log

mkdir -p "$DATA_DIR" "$WORKSPACE" "$PROFILE_DIR" /data/local/tmp/android-sec-mcp
chmod 700 "$DATA_DIR" "$PROFILE_DIR" /data/local/tmp/android-sec-mcp 2>/dev/null
chmod 755 "$DAEMON" 2>/dev/null
[ -f "$BUNDLED_FRIDA" ] && chmod 755 "$BUNDLED_FRIDA" 2>/dev/null

# Copy bundled default bypass profiles on first install/update without overwriting user profiles.
if [ -d "$MODDIR/bypass-profiles" ]; then
  for p in "$MODDIR"/bypass-profiles/*.json; do
    [ -f "$p" ] || continue
    base=$(basename "$p")
    [ -f "$PROFILE_DIR/$base" ] || cp "$p" "$PROFILE_DIR/$base"
  done
fi

# Wait until Android boot is complete so pm/dumpsys are available.
for i in $(seq 1 120); do
  [ "$(getprop sys.boot_completed)" = "1" ] && break
  sleep 1
done

# Prefer an existing frida-server on the device. The module's bundled frida-server
# may be a placeholder unless the user replaced it before packaging.
detect_frida() {
  for p in \
    /data/local/tmp/frida-server \
    /data/adb/frida-server \
    /data/local/frida-server \
    /system/bin/frida-server \
    "$BUNDLED_FRIDA"; do
    [ -f "$p" ] && [ -x "$p" ] && echo "$p" && return 0
  done
  echo "/data/local/tmp/frida-server"
}
FRIDA_PATH=$(detect_frida)

# If config does not exist, let daemon create it once, then patch fridaServerPath.
if [ ! -f "$CONFIG" ]; then
  "$DAEMON" --config "$CONFIG" --print-token >/dev/null 2>&1
fi

# Best-effort patch fridaServerPath in config without changing token or other fields.
if [ -f "$CONFIG" ]; then
  if command -v sed >/dev/null 2>&1; then
    sed -i "s#\"fridaServerPath\"[[:space:]]*:[[:space:]]*\"[^\"]*\"#\"fridaServerPath\": \"$FRIDA_PATH\"#" "$CONFIG" 2>/dev/null
  fi
fi

# Stop stale daemon started from previous module version.
pidof android-sec-mcp >/dev/null 2>&1 && kill $(pidof android-sec-mcp) 2>/dev/null

nohup "$DAEMON" --config "$CONFIG" >>"$LOG" 2>&1 &
