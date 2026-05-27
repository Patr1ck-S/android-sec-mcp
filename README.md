# android-sec-mcp

[中文文档](README.zh-CN.md)

`android-sec-mcp` is an Android root-side MCP daemon for CTFs, labs, self-owned apps, and explicitly authorized Android security research.

> Do **not** use it against third-party apps, devices, services, accounts, or networks without permission.

## Overview

- Daemon: `android-sec-mcp`, written in Go and intended to run with root privileges.
- Deployment: Magisk module.
- Default bind address: `127.0.0.1:8765`.
- PC access: `adb forward tcp:8765 tcp:8765`.
- MCP transport: HTTP JSON-RPC endpoint at `POST /mcp`.
- Authentication: every HTTP request must include `Authorization: Bearer <token>`.
- Audit log: `/data/adb/android-sec-mcp/audit.log`.
- Workspace: `/data/local/tmp/android-sec-mcp/cases/`.
- Config: `/data/adb/android-sec-mcp/config.json`.

## Safety Model

- Intended only for CTFs, labs, self-owned apps, and authorized Android security testing.
- The daemon refuses to listen on non-loopback addresses by default.
- All requests require a bearer token.
- High-risk tools require `confirm=true`.
- CTF bypass mode is disabled by default.
- Bypass actions require:
  - `ctfBypassEnabled=true`
  - target package in `allowedBypassPackages`
  - `confirm=true` in MCP arguments
- Bypass profiles are target-scoped runtime Frida scripts; they do not patch the whole system.
- Bypass actions are written to `audit.log`.

## Project Layout

```text
daemon/
  main.go
  server/
  tools/
  caseflow/
  safety/
magisk/
  module.prop
  service.sh
  uninstall.sh
  system/bin/
  bypass-profiles/
scripts/
examples/
```

## Build

Android arm64:

```bash
cd android-sec-mcp
./scripts/build_android.sh
```

Package Magisk module:

```bash
./scripts/package_magisk.sh
```

Output:

```text
build/android-sec-mcp-magisk.zip
```

## Installation

Push the module to the device:

```bash
adb push build/android-sec-mcp-magisk.zip /sdcard/Download/
```

Install it in the Magisk app and reboot.

Read the token:

```bash
adb shell su -c 'cat /data/adb/android-sec-mcp/config.json'
# or
adb shell su -c '/system/bin/android-sec-mcp --config /data/adb/android-sec-mcp/config.json --print-token'
```

Forward the port:

```bash
adb forward tcp:8765 tcp:8765
export ANDROID_SEC_MCP_TOKEN='<token from config.json>'
```

Health check:

```bash
curl -sS http://127.0.0.1:8765/health \
  -H "Authorization: Bearer $ANDROID_SEC_MCP_TOKEN"
```

List MCP tools:

```bash
curl -sS http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $ANDROID_SEC_MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## MCP Client Example

```json
{
  "mcpServers": {
    "android-sec-mcp": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_WITH_TOKEN_FROM_DEVICE"
      }
    }
  }
}
```

Example client configs are in `examples/`.

## Tools

Major tool groups:

- Device: `device.info`, `device.props`, `device.battery`, `device.screen_size`
- App management: `app.list_packages`, `app.find_package`, `app.package_info`, `app.path`, `app.pull_apk`
- App components: `app.permissions`, `app.activities`, `app.services`, `app.receivers`, `app.providers`, `app.exported_components`
- Runtime: `runtime.foreground_package`, `runtime.current_activity`, `runtime.pid_by_package`
- Screen/UI: `screen.screenshot`, `ui.dump_xml`, `ui.summary`
- Logcat: `logcat.clear`, `logcat.tail`, `logcat.by_pid`, `logcat.by_package`, `logcat.grep`
- Frida: `frida.status`, `frida.server_start`, `frida.server_stop`, `frida.list_processes`, `frida.attach`, `frida.load_script`, `frida.collect_messages`
- Frida PC mode: `frida.prepare_pc_script`, `frida.ingest_pc_result`, `frida.pc_spawn_command`
- Case workflow: `case.create`, `case.run_basic_recon`, `case.run_login_analysis`, `case.export_report`, `case.get_report`
- CTF analysis: `ctf.scan_detection_points`, `ctf.classify_protection`, `ctf.generate_bypass_plan`, `ctf.list_bypass_profiles`, `ctf.apply_bypass_profile`, `ctf.revert_bypass_profile`, `ctf.prepare_debugger_bypass`

CTF detection currently covers:

- root detection
- debugger detection
- emulator detection
- Frida detection
- traffic capture / SSL pinning / proxy / VPN detection

## Frida Notes

A real `frida-server` binary is not bundled by default. Put a matching official `frida-server` on the device or replace `magisk/system/bin/frida-server` locally before packaging.

The daemon checks common paths such as:

```text
/data/local/tmp/frida-server
/data/adb/frida-server
/data/local/frida-server
/system/bin/frida-server
```

Recommended mode:

- Android runs `frida-server`.
- PC/Mac runs `frida-tools`.
- MCP generates scripts and PC-side commands.
- PC-side Frida output can be ingested back into the MCP session.

## Troubleshooting

### Daemon does not start

Check the daemon log first:

```sh
su -c 'tail -100 /data/adb/android-sec-mcp/daemon.log'
```

### Frida features are unavailable

Confirm the following:

- `frida-server` is a real executable file
- `fridaServerPath` points to the correct path
- the `frida-server` process is running

Example checks:

```sh
su -c 'ls -l /data/local/tmp/frida-server /data/adb/frida-server /system/bin/frida-server 2>/dev/null'
su -c 'pidof frida-server'
```

### MCP client says unauthorized or token is invalid

Confirm:

- you are using the token from `/data/adb/android-sec-mcp/config.json`
- the request header is `Authorization: Bearer <token>`

### Bypass request is rejected

Confirm:

- `ctfBypassEnabled` is enabled
- the target package is in `allowedBypassPackages`
- the MCP request includes `confirm=true`

### Service is reachable, but Frida actions still fail

This usually means the daemon is alive but Frida is not ready. Check both:

- `/data/adb/android-sec-mcp/daemon.log`
- device-side `frida-server` process status

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
