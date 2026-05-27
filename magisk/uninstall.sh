#!/system/bin/sh
pidof android-sec-mcp >/dev/null 2>&1 && kill $(pidof android-sec-mcp) 2>/dev/null
# Keep /data/adb/android-sec-mcp and /data/local/tmp/android-sec-mcp/cases by default for auditability.
# Remove manually if desired:
# rm -rf /data/adb/android-sec-mcp /data/local/tmp/android-sec-mcp
