# android-sec-mcp

[English](README_EN.md)

> 仅用于 CTF、靶场、自研 App、授权 Android App 的安全研究和逆向分析。

## 法律与安全声明

本项目仅用于 CTF、靶场、实验室、自研 App、以及已获得明确授权的 Android 安全研究。

请勿在未授权的第三方 App、设备、服务、账号或网络上使用。本 daemon 可能以 Android root 权限运行；请保持只监听 `127.0.0.1`，妥善保管 bearer token，并在执行高风险动作后检查 `audit.log`。

本项目实现一个通过 Magisk 模块安装的 Android root MCP daemon：

- daemon：`android-sec-mcp`，Go 编写，root 权限长期运行。
- 默认监听：`127.0.0.1:8765`，不会监听 `0.0.0.0`。
- 电脑端访问：`adb forward tcp:8765 tcp:8765`。
- MCP Transport：Streamable HTTP 风格 JSON-RPC endpoint：`POST /mcp`。
- 鉴权：所有 HTTP 请求必须携带 `Authorization: Bearer <token>`。
- 审计：每次 MCP tool 调用写入 `/data/adb/android-sec-mcp/audit.log`。
- workspace：`/data/local/tmp/android-sec-mcp/cases/`。
- config：`/data/adb/android-sec-mcp/config.json`。

## 目录结构

```text
daemon/
  main.go
  server/{mcp_http.go,router.go,auth.go,...}
  tools/{device.go,app.go,activity.go,logcat.go,screen.go,ui.go,frida.go,case.go,ctf.go}
  caseflow/{case.go,login_analysis.go,report.go}
  safety/{policy.go,guard.go}
magisk/
  module.prop
  service.sh
  uninstall.sh
  system/bin/android-sec-mcp
  system/bin/frida-server
  bypass-profiles/*.json
scripts/
examples/
```

## 安全模型

1. 仅用于授权 App、CTF、靶场、自研 App。
2. 默认只监听 `127.0.0.1:8765`。
3. 所有请求必须校验 Bearer Token。
4. 高风险工具需要 `confirm: true`。
5. CTF Bypass Mode 默认关闭：`ctfBypassEnabled=false`。
6. Bypass 必须同时满足：
   - `ctfBypassEnabled=true`
   - `packageName` 在 `allowedBypassPackages`
   - MCP tool 参数 `confirm=true`
7. bypass profile 只以 Frida runtime 方式注入目标 package 进程，不做全局系统 patch。
8. 所有 bypass 操作都会写入 `audit.log`。

## 编译

### Android arm64：

```bash
cd ./android-sec-mcp
./scripts/build_android.sh
```

等价手动命令：

```bash
cd ./android-sec-mcp
mkdir -p build .gocache
GOOS=android GOARCH=arm64 CGO_ENABLED=0 GOCACHE=$PWD/.gocache \
  go build -trimpath -ldflags "-s -w" -o build/android-sec-mcp ./daemon
cp build/android-sec-mcp magisk/system/bin/android-sec-mcp
chmod 755 magisk/system/bin/android-sec-mcp
```

### Android x86_64 模拟器 / amd64

Android `amd64` 目标需要外部链接器，因此不能直接使用默认的
`CGO_ENABLED=0` 构建；需要先安装 Android NDK，并使用 NDK 里的
`x86_64-linux-androidXX-clang` 作为 `CC`。

macOS Homebrew 示例：

```bash
brew install --cask android-ndk
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
export NDK_PREBUILT="$(ls -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/"* | head -n 1)"
export CC="$NDK_PREBUILT/bin/x86_64-linux-android24-clang"
```

构建 x86_64 模拟器二进制：

```bash
cd ./android-sec-mcp
mkdir -p build .gocache
GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC="$CC" GOCACHE=$PWD/.gocache \
  go build -trimpath -ldflags "-s -w" -o build/android-sec-mcp ./daemon
cp build/android-sec-mcp magisk/system/bin/android-sec-mcp
chmod 755 magisk/system/bin/android-sec-mcp
```

打包并保存为 amd64 专用包：

```bash
./scripts/package_magisk.sh
cp build/android-sec-mcp-magisk.zip build/android-sec-mcp-magisk-android-amd64.zip
```

> 注意：上述步骤会把 `magisk/system/bin/android-sec-mcp` 替换成 amd64
> 版本。如果之后要打 arm64 真机包，需要重新执行 arm64 构建。


## 打包 Magisk 模块

```bash
./scripts/package_magisk.sh
# 输出 build/android-sec-mcp-magisk.zip
```

## 安装

```bash
adb push build/android-sec-mcp-magisk.zip /sdcard/Download/
```

然后在 Magisk App 中安装该 zip 并重启。重启后服务脚本会启动：

```text
/data/adb/android-sec-mcp/config.json
/data/adb/android-sec-mcp/audit.log
/data/local/tmp/android-sec-mcp/cases/
```

查看 daemon 日志：

```bash
adb shell su -c 'tail -n 100 /data/adb/android-sec-mcp/daemon.log'
```

读取 token：

```bash
adb shell su -c 'cat /data/adb/android-sec-mcp/config.json'
# 或
adb shell su -c '/system/bin/android-sec-mcp --config /data/adb/android-sec-mcp/config.json --print-token'
```

## adb forward

```bash
adb forward tcp:8765 tcp:8765
export ANDROID_SEC_MCP_TOKEN='<config.json 里的 token>'
```

健康检查：

```bash
curl -sS http://127.0.0.1:8765/health \
  -H "Authorization: Bearer $ANDROID_SEC_MCP_TOKEN" | jq .
```

列出 MCP tools：

```bash
curl -sS http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $ANDROID_SEC_MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .
```

## MCP Client 配置示例

### Cursor / Codex / 支持 remote HTTP MCP 的客户端

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

### Claude Desktop（用 mcp-remote 适配 HTTP）

```json
{
  "mcpServers": {
    "android-sec-mcp": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:8765/mcp",
        "--header",
        "Authorization: Bearer REPLACE_WITH_TOKEN_FROM_DEVICE"
      ]
    }
  }
}
```

示例文件位于 `examples/`。

## MCP tools

| 类别 | 工具 | 说明 |
|---|---|---|
| 设备信息 | `device.info` `device.props` `device.battery` `device.screen_size` | 获取设备基础信息、系统属性、电池状态、屏幕尺寸与密度 |
| App 管理 | `app.list_packages` `app.find_package` `app.package_info` `app.path` `app.pull_apk` | 枚举/搜索 App、查看包信息、获取 APK 路径、复制 APK 到 workspace |
| App 组件 | `app.permissions` `app.activities` `app.services` `app.receivers` `app.providers` `app.exported_components` | 分析权限、Activity/Service/Receiver/Provider、导出组件 |
| App 运行控制 | `app.launch` `app.force_stop` (`confirm=true`) | 启动 App、强制停止 App |
| 运行态 | `runtime.foreground_package` `runtime.current_activity` `runtime.pid_by_package` | 获取前台包名、当前 Activity、根据包名查 PID |
| 截图 | `screen.screenshot` | 截取当前屏幕并保存到设备路径 |
| UI / 无障碍 | `ui.dump_xml` `ui.summary` | dump 当前 UI XML、提取可见节点摘要 |
| Logcat | `logcat.clear` `logcat.tail` `logcat.by_pid` `logcat.by_package` `logcat.grep` | 清空/读取 logcat，按 PID、包名、关键字或正则过滤日志 |
| Frida 基础 | `frida.status` `frida.server_start` (`confirm=true`) `frida.server_stop` (`confirm=true`) `frida.list_processes` | 检查 Frida 状态、启动/停止 frida-server、列出进程 |
| Frida 会话 | `frida.attach` (`confirm=true`) `frida.load_script` (`confirm=true`) `frida.collect_messages` | 创建 Frida session、加载脚本、收集 session 输出 |
| Frida PC 模式 | `frida.prepare_pc_script` `frida.ingest_pc_result` `frida.pc_spawn_command` | 保存 JS 到移动端、生成 PC 端 adb/frida 命令、回传 PC 端 Frida 输出、生成 spawn 早期注入命令 |
| Frida 模板 | `frida.template_trace_method` `frida.template_trace_class` | 生成 Java 方法/类的 observation-only trace 脚本 |
| Case 流程 | `case.create` `case.run_basic_recon` `case.run_login_analysis` (`confirm=true`) | 创建 case、执行基础侦察、执行登录分析流程 |
| Case 报告 | `case.export_report` `case.get_report` | 导出 case zip、读取 `report.md` |
| CTF 检测 | `ctf.scan_detection_points` `ctf.classify_protection` `ctf.generate_bypass_plan` | 扫描 root/debugger/emulator/frida/抓包对抗(SSL pinning、proxy/VPN) 检测点、分类防护等级、生成 bypass plan |
| CTF Profile | `ctf.list_bypass_profiles` `ctf.apply_bypass_profile` (`confirm=true`) `ctf.revert_bypass_profile` (`confirm=true`) `ctf.run_target_with_profile` (`confirm=true`) | 列出/应用/回滚 target-scoped runtime bypass profile，或启动目标后应用 profile |
| CTF 报告 / 自动化 | `ctf.export_bypass_report` `ctf.prepare_debugger_bypass` (`confirm=true`) | 导出 bypass 报告；自动检测反调试、生成 anti-debug Frida JS、返回 PC 端注入流程 |



Profile 目录：

```text
/data/adb/android-sec-mcp/bypass-profiles/
```

Profile JSON 字段：

```json
{
  "name": "root-basic",
  "description": "...",
  "scope": "target-package-runtime",
  "allowedUse": "Only CTF/lab/self-owned/authorized testing",
  "protections": ["root_detection"],
  "requiresConfirm": true,
  "actions": [
    {
      "type": "java_return",
      "className": "com.example.RootCheck",
      "methodName": "isRooted",
      "returnType": "boolean",
      "returnValue": false
    }
  ],
  "revert": [
    {"type": "detach", "description": "Detach Frida session"}
  ]
}
```

开启 CTF Bypass Mode（示例仅允许 `com.example.app`）：

```bash
adb shell su -c 'cat > /data/adb/android-sec-mcp/config.json.tmp <<EOF
{
  "bindAddr": "127.0.0.1:8765",
  "token": "REPLACE_WITH_EXISTING_TOKEN",
  "workspaceDir": "/data/local/tmp/android-sec-mcp/cases",
  "dataDir": "/data/adb/android-sec-mcp",
  "auditLogPath": "/data/adb/android-sec-mcp/audit.log",
  "fridaServerPath": "/system/bin/frida-server",
  "fridaCliPath": "",
  "fridaHost": "127.0.0.1:27042",
  "commandTimeoutSeconds": 30,
  "maxLogcatLines": 500,
  "ctfBypassEnabled": true,
  "allowedBypassPackages": ["com.example.app"],
  "bypassProfilesDir": "/data/adb/android-sec-mcp/bypass-profiles"
}
EOF
mv /data/adb/android-sec-mcp/config.json.tmp /data/adb/android-sec-mcp/config.json
kill $(pidof android-sec-mcp) 2>/dev/null
/system/bin/android-sec-mcp --config /data/adb/android-sec-mcp/config.json >>/data/adb/android-sec-mcp/daemon.log 2>&1 &'
```

## Demo：对 `com.example.app` 执行 basic recon 并生成 report.md

```bash
adb forward tcp:8765 tcp:8765
export ANDROID_SEC_MCP_TOKEN='<token>'
./scripts/demo_basic_recon.sh
```

等价 curl：

```bash
curl -sS http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $ANDROID_SEC_MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @examples/case_basic_recon_request.json | jq .
```

返回示例中会包含：

```json
{
  "caseDir": "/data/local/tmp/android-sec-mcp/cases/20260522-xxxxxx-com.example.app",
  "reportPath": "/data/local/tmp/android-sec-mcp/cases/20260522-xxxxxx-com.example.app/report.md"
}
```

读取 report：

```bash
./scripts/call_tool.sh case.get_report '{"caseDir":"/data/local/tmp/android-sec-mcp/cases/CASE_ID"}'
```

## Login Analysis + Bypass 示例

```bash
curl -sS http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $ANDROID_SEC_MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @examples/login_analysis_with_bypass_request.json | jq .
```

`report.md` 会增加 `CTF Bypass Mode` 章节，记录：检测点、profile、作用范围、加载时间、是否 revert。

## 审计日志

```bash
adb shell su -c 'tail -n 50 /data/adb/android-sec-mcp/audit.log'
```

每条记录是 JSONL，包含 tool 名、参数摘要、状态、耗时，以及 bypass apply/revert 事件。

## Frida server

如果设备上已经有 `frida-server`，不需要替换模块内文件。模块启动时会自动优先检测：

1. `/data/local/tmp/frida-server`
2. `/data/adb/frida-server`
3. `/data/local/frida-server`
4. `/system/bin/frida-server`
5. 模块内 `system/bin/frida-server`

`magisk/system/bin/frida-server` 当前只是占位脚本。如果设备上没有已有的 `frida-server`，打包前再替换为与你设备 ABI 匹配的官方 `frida-server`：

```bash
cp /path/to/frida-server-android-arm64 magisk/system/bin/frida-server
chmod 755 magisk/system/bin/frida-server
```

daemon 能启动/停止 `frida-server`。

### 模式 1：设备端自动加载 JS

如果要让 daemon 在 Android 设备端自己加载 JS，需要在配置中设置一个设备端可用的 Frida CLI/注入器路径：

```json
"fridaCliPath": "/data/local/tmp/frida"
```

### 模式 2：PC 端 Frida CLI 加载 JS（推荐）


- Android 设备只运行 `frida-server`
- PC/Mac 安装 `frida-tools`
- PC/Mac 使用 `frida -U` 或 `frida -H 127.0.0.1:27042` 加载 JS

PC 端安装：

```bash
pipx install frida-tools
# 或
pip install frida-tools
```

如果 `fridaCliPath` 为空，daemon 会进入 PC-side mode：

- Frida 脚本仍会生成到 case 目录
- MCP 返回结果中的 `pcMode.script` 会包含脚本内容
- `pcMode.commands` 会给出：从设备导出 JS 到本地、attach 注入、spawn 早期注入命令

典型 PC 端命令：

```bash
# 1. 从 MCP 返回的 pcMode.scriptPathOnDevice 导出 JS 到本地
adb exec-out su -c "cat '/data/local/tmp/android-sec-mcp/cases/.../frida/login_observation.js'" > hook.js

# 如果该路径对 adb shell 可读，也可以：
adb pull '/data/local/tmp/android-sec-mcp/cases/.../frida/login_observation.js' hook.js

# 2. 先确保设备端 frida-server 已运行，然后 attach 注入
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -p <PID> -l hook.js

# 或者直接通过 USB 设备 attach
frida -U -p <PID> -l hook.js
```

#### Spawn 早期注入

如果目标 App 在 `Application.attachBaseContext()`、`Application.onCreate()` 或更早阶段做 root/debug/frida 检测，普通 attach 可能太晚。此时使用 spawn 方式从 PC 端启动目标 App 并提前加载脚本：

```bash
# 先从设备导出 MCP 生成的 JS 到本地 hook.js
adb exec-out su -c "cat '/data/local/tmp/android-sec-mcp/cases/.../frida/login_observation.js'" > hook.js

# 再执行 spawn 早期注入
frida -U -f com.example.app -l hook.js

# 或者通过 adb forward 连接 frida-server
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -f com.example.app -l hook.js
```

也可以让 MCP 生成命令：

```bash
./scripts/call_tool.sh frida.pc_spawn_command '{"packageName":"com.example.app","scriptName":"hook.js"}'
```

#### 本地 helper：生成、拉取、注入、回传结果

如果要把流程自动串起来，可以使用：

```bash
ANDROID_SEC_MCP_TOKEN='<token>' \
  ./scripts/frida_pc_load.sh spawn com.example.app hook.js
```

或 attach 到已运行进程：

```bash
ANDROID_SEC_MCP_TOKEN='<token>' \
  ./scripts/frida_pc_load.sh attach com.example.app hook.js
```

helper 会自动执行：

1. 调用 MCP `frida.prepare_pc_script`，把本地 `hook.js` 保存到移动端 case 目录。
2. 通过 `adb exec-out su -c "cat <device-js>" > <local-js>` 把移动端生成的 JS 拉回本地。
3. 使用 PC 端 `frida` 执行 attach 或 spawn 注入。
4. 调用 MCP `frida.ingest_pc_result`，把 Frida 输出回传到 MCP session。
5. 调用 MCP `frida.collect_messages`，输出 MCP 侧汇总结果，方便继续分析。

可选环境变量：

```bash
export ANDROID_SEC_MCP_URL='http://127.0.0.1:8765/mcp'
export FRIDA_PC_WAIT=10
export FRIDA_HOST='127.0.0.1:27042'   # 设置后使用 -H，否则默认 -U
export FRIDA_LOCAL_DIR='build/frida-pc'
```

##### 自动反调试检测 + 生成 bypass + 注入

如果要让 MCP 自动扫描 debugger 检测点并生成反调试脚本：

```bash
ANDROID_SEC_MCP_TOKEN='<token>' \
  ./scripts/frida_pc_load.sh spawn com.example.app --auto-debug
```

或 attach：

```bash
ANDROID_SEC_MCP_TOKEN='<token>' \
  ./scripts/frida_pc_load.sh attach com.example.app --auto-debug
```

该流程会自动执行：

1. MCP `ctf.prepare_debugger_bypass` 扫描 APK 中的 debugger 检测点。
2. 自动生成 anti-debug Frida JS。
3. JS 保存到移动端 case/frida 目录。
4. adb 导出 JS 到本地。
5. PC 端执行 Frida spawn/attach 注入。
6. Frida 输出通过 `frida.ingest_pc_result` 回传 MCP。
7. MCP 通过 `frida.collect_messages` 汇总结果。

生成的 anti-debug 脚本会尝试处理：

- `android.os.Debug.isDebuggerConnected()`
- `android.os.Debug.waitingForDebugger()`
- `android.os.Debug.waitForDebugger()`
- `/proc/self/status` 中的 `TracerPid`
- native `ptrace`
- `syscall(ptrace)`

检测结果会包含更细的字段：

```json
{
  "protection": "debugger_detection",
  "category": "java_debug_api",
  "rule": "debug_is_debugger_connected",
  "keyword": "isDebuggerConnected",
  "confidence": "high"
}
```

当前 debugger 检测会重点识别：

- Java Debug API：`android.os.Debug`、`isDebuggerConnected`、`waitingForDebugger`、`waitForDebugger`
- proc 状态检测：`/proc/self/status`、`/proc/self/task`、`TracerPid`
- native 调试 API：`ptrace`、`PTRACE_TRACEME`
- 系统属性：`ro.debuggable`
- JDWP 相关字符串：`jdwp` / `JDWP`
- 常见命名痕迹：`anti_debug` / `antiDebug`

> 该工具属于 bypass 流程，需要配置 `ctfBypassEnabled=true`，目标包名在
> `allowedBypassPackages` 中，并传入 `confirm=true`。helper 已自动传入
> `confirm=true`。

## 手动指定 frida-server 路径

如果自动检测结果不符合预期，也可以手动指定：

```bash
adb shell su -c 'grep fridaServerPath /data/adb/android-sec-mcp/config.json'
adb shell su -c 'sed -i "s#\"fridaServerPath\": \"[^\"]*\"#\"fridaServerPath\": \"/data/local/tmp/frida-server\"#" /data/adb/android-sec-mcp/config.json'
adb shell su -c 'kill $(pidof android-sec-mcp) 2>/dev/null; /system/bin/android-sec-mcp --config /data/adb/android-sec-mcp/config.json >>/data/adb/android-sec-mcp/daemon.log 2>&1 &'
```

检查：

```bash
adb shell su -c 'ls -l /data/local/tmp/frida-server; pidof frida-server'
./scripts/call_tool.sh frida.status '{}'
```

## 排错

### 守护进程没有启动

先看日志：

```sh
su -c 'tail -100 /data/adb/android-sec-mcp/daemon.log'
```

### Frida 相关功能不可用

确认以下几点：

- `frida-server` 是真实可执行文件
- `fridaServerPath` 指向正确路径
- `frida-server` 进程已经运行

示例检查命令：

```sh
su -c 'ls -l /data/local/tmp/frida-server /data/adb/frida-server /system/bin/frida-server 2>/dev/null'
su -c 'pidof frida-server'
```

### MCP 客户端提示未授权或 token 错误

确认：

- 使用的是 `/data/adb/android-sec-mcp/config.json` 中的 token
- 请求头使用的是 `Authorization: Bearer <token>`

### Bypass 请求被拒绝

确认：

- `ctfBypassEnabled` 已开启
- 目标包名在 `allowedBypassPackages` 中
- MCP 请求里带了 `confirm=true`

### 服务可以访问，但 Frida 动作仍然失败

这通常说明守护进程活着，但 Frida 本身没有准备好。请同时检查：

- `/data/adb/android-sec-mcp/daemon.log`
- 设备侧 `frida-server` 进程状态

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
