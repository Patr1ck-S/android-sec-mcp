package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func registerFrida(reg *server.Registry) {
	reg.Register(server.Tool{Name: "frida.status", Description: "Check frida-server process status and configured paths.", InputSchema: server.ObjectSchema(nil, nil), Handler: fridaStatus})
	reg.Register(server.Tool{Name: "frida.server_start", Description: "Start configured frida-server. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"confirm": server.BoolProp("Required true")}, []string{"confirm"}), Handler: fridaServerStart})
	reg.Register(server.Tool{Name: "frida.server_stop", Description: "Stop frida-server. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"confirm": server.BoolProp("Required true")}, []string{"confirm"}), Handler: fridaServerStop})
	reg.Register(server.Tool{Name: "frida.list_processes", Description: "List processes visible from the daemon; uses frida CLI if configured, otherwise ps.", InputSchema: server.ObjectSchema(nil, nil), Handler: fridaListProcesses})
	reg.Register(server.Tool{Name: "frida.attach", Description: "Create a target-scoped Frida session record for a PID/package. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "pid": server.IntProp("Target PID"), "confirm": server.BoolProp("Required true")}, []string{"confirm"}), Handler: fridaAttach})
	reg.Register(server.Tool{Name: "frida.load_script", Description: "Load a Frida JavaScript file/string into a recorded session if fridaCliPath is configured. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"sessionId": server.StringProp("Session id from frida.attach"), "script": server.StringProp("JavaScript source"), "scriptPath": server.StringProp("Existing JS path"), "confirm": server.BoolProp("Required true")}, []string{"sessionId", "confirm"}), Handler: fridaLoadScript})
	reg.Register(server.Tool{Name: "frida.collect_messages", Description: "Collect buffered stdout/stderr messages for a Frida session.", InputSchema: server.ObjectSchema(map[string]any{"sessionId": server.StringProp("Session id"), "limit": server.IntProp("Max messages")}, []string{"sessionId"}), Handler: fridaCollectMessages})
	reg.Register(server.Tool{Name: "frida.prepare_pc_script", Description: "Save a Frida JS script on Android and return PC-side adb export + frida injection commands.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "script": server.StringProp("JavaScript source"), "prefix": server.StringProp("Output filename prefix")}, []string{"packageName", "script"}), Handler: fridaPreparePCScript})
	reg.Register(server.Tool{Name: "frida.ingest_pc_result", Description: "Append PC-side Frida execution output back into a Frida session for MCP-side analysis.", InputSchema: server.ObjectSchema(map[string]any{"sessionId": server.StringProp("Session id"), "command": server.StringProp("Executed PC command"), "exitCode": server.IntProp("PC command exit code"), "output": server.StringProp("Captured stdout/stderr"), "mode": server.StringProp("attach or spawn")}, []string{"sessionId"}), Handler: fridaIngestPCResult})
	reg.Register(server.Tool{Name: "frida.template_trace_method", Description: "Generate an observation-only Java method trace Frida script.", InputSchema: server.ObjectSchema(map[string]any{"className": server.StringProp("Java class name"), "methodName": server.StringProp("Java method name")}, []string{"className", "methodName"}), Handler: fridaTemplateTraceMethod})
	reg.Register(server.Tool{Name: "frida.template_trace_class", Description: "Generate an observation-only Java class trace Frida script.", InputSchema: server.ObjectSchema(map[string]any{"className": server.StringProp("Java class name")}, []string{"className"}), Handler: fridaTemplateTraceClass})
	reg.Register(server.Tool{Name: "frida.pc_spawn_command", Description: "Generate PC-side Frida spawn early-injection commands for `frida -f package -l script.js`.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "scriptName": server.StringProp("Local JS filename on PC, default hook.js"), "host": server.StringProp("Forwarded frida-server host, default 127.0.0.1:27042")}, []string{"packageName"}), Handler: fridaPCSpawnCommand})
}

func fridaStatus(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pidof := env.Exec(ctx, 5*time.Second, "pidof", "frida-server")
	existsServer := fileExists(env.Config.FridaServerPath)
	existsCli := env.Config.FridaCliPath != "" && fileExists(env.Config.FridaCliPath)
	return map[string]any{"running": pidof.ExitCode == 0, "pidof": strings.TrimSpace(pidof.Stdout), "fridaServerPath": env.Config.FridaServerPath, "fridaServerExists": existsServer, "fridaCliPath": env.Config.FridaCliPath, "fridaCliExists": existsCli, "fridaHost": env.Config.FridaHost}, nil
}

func fridaServerStart(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "frida.server_start"); err != nil {
		return nil, err
	}
	st, _ := fridaStatus(ctx, env, args)
	if st.(map[string]any)["running"].(bool) {
		return st, nil
	}
	if !fileExists(env.Config.FridaServerPath) {
		return nil, fmt.Errorf("frida-server not found at %s", env.Config.FridaServerPath)
	}
	cmd := execCommandNoWait(env.Config.FridaServerPath)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	time.Sleep(800 * time.Millisecond)
	st, _ = fridaStatus(ctx, env, args)
	env.Audit.Log("frida.server_start", map[string]any{"path": env.Config.FridaServerPath, "pid": cmd.Process.Pid})
	return map[string]any{"startedPid": cmd.Process.Pid, "status": st}, nil
}

func fridaServerStop(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "frida.server_stop"); err != nil {
		return nil, err
	}
	pidof := env.Exec(ctx, 5*time.Second, "pidof", "frida-server")
	pids := strings.Fields(pidof.Stdout)
	killed := []string{}
	for _, pid := range pids {
		r := env.Exec(ctx, 5*time.Second, "kill", pid)
		if r.ExitCode == 0 {
			killed = append(killed, pid)
		}
	}
	env.Audit.Log("frida.server_stop", map[string]any{"pids": pids, "killed": killed})
	return map[string]any{"pids": pids, "killed": killed}, nil
}

func fridaListProcesses(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if env.Config.FridaCliPath != "" && fileExists(env.Config.FridaCliPath) {
		r := env.Exec(ctx, 20*time.Second, env.Config.FridaCliPath, "-H", env.Config.FridaHost, "-ps")
		return map[string]any{"backend": "frida-cli", "result": commandJSON(r)}, nil
	}
	r := env.Exec(ctx, 10*time.Second, "ps", "-A")
	return map[string]any{"backend": "ps", "lines": outputLines(r.Stdout), "result": commandJSON(r)}, nil
}

func fridaAttach(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "frida.attach"); err != nil {
		return nil, err
	}
	pkg := strArg(args, "packageName", "")
	pid := intArg(args, "pid", 0)
	if pkg != "" {
		if err := safety.ValidatePackageName(pkg); err != nil {
			return nil, err
		}
		if pid == 0 {
			pid, _ = pidByPackage(ctx, env, pkg)
		}
	}
	if pid <= 0 {
		return nil, fmt.Errorf("pid or packageName resolving to a PID is required")
	}
	sess := env.Sessions.New(pkg, pid)
	env.Audit.Log("frida.attach", map[string]any{"sessionId": sess.ID, "packageName": pkg, "pid": pid})
	return sess, nil
}

func fridaLoadScript(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "frida.load_script"); err != nil {
		return nil, err
	}
	id := strArg(args, "sessionId", "")
	sess, ok := env.Sessions.Get(id)
	if !ok {
		return nil, fmt.Errorf("unknown sessionId %s", id)
	}
	scriptPath := strArg(args, "scriptPath", "")
	script := strArg(args, "script", "")
	if scriptPath == "" {
		if script == "" {
			return nil, fmt.Errorf("script or scriptPath required")
		}
		p, err := safeJoin(env.Config.WorkspaceDir, "frida", "scripts", safety.SafeName(id)+".js")
		if err != nil {
			return nil, err
		}
		if err := writeTextFile(p, script); err != nil {
			return nil, err
		}
		scriptPath = p
	}
	loaded, err := env.StartFridaScript(ctx, sess, scriptPath)
	env.Audit.Log("frida.load_script", map[string]any{"sessionId": id, "packageName": sess.PackageName, "pid": sess.PID, "scriptPath": scriptPath, "loaded": loaded != nil && loaded.Loaded, "error": errString(err)})
	if err != nil {
		return nil, err
	}
	return loaded, nil
}

func fridaCollectMessages(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	id := strArg(args, "sessionId", "")
	sess, ok := env.Sessions.Get(id)
	if !ok {
		return nil, fmt.Errorf("unknown sessionId %s", id)
	}
	limit := intArg(args, "limit", 200)
	msgs := sess.Messages
	if limit > 0 && len(msgs) > limit {
		msgs = msgs[len(msgs)-limit:]
	}
	return map[string]any{"sessionId": id, "loaded": sess.Loaded, "note": sess.Note, "pcMode": sess.PCMode, "messages": msgs, "count": len(msgs)}, nil
}

func fridaPreparePCScript(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	script := strArg(args, "script", "")
	if script == "" {
		return nil, fmt.Errorf("script required")
	}
	prefix := strArg(args, "prefix", "pc-frida")
	pid, _ := pidByPackage(ctx, env, pkg)
	scriptPath, err := writeScriptForPackage(env, pkg, prefix, script)
	if err != nil {
		return nil, err
	}
	sess := env.Sessions.New(pkg, pid)
	sess.ScriptPath = scriptPath
	sess.Loaded = false
	sess.Note = "pc-side mode prepared; export the generated JS with adb, then inject it from PC frida-tools"
	sess.PCMode = server.BuildPCMode(sess, scriptPath, sess.Note)
	env.Sessions.Put(sess)
	env.Audit.Log("frida.prepare_pc_script", map[string]any{"sessionId": sess.ID, "packageName": pkg, "pid": pid, "scriptPath": scriptPath})
	return map[string]any{"packageName": pkg, "pid": pid, "scriptPath": scriptPath, "session": sess, "pcMode": sess.PCMode}, nil
}

func fridaIngestPCResult(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	id := strArg(args, "sessionId", "")
	sess, ok := env.Sessions.Get(id)
	if !ok {
		return nil, fmt.Errorf("unknown sessionId %s", id)
	}
	mode := strArg(args, "mode", "")
	command := strArg(args, "command", "")
	exitCode := intArg(args, "exitCode", 0)
	output := strArg(args, "output", "")
	header := fmt.Sprintf("[pc-frida] mode=%s exit=%d command=%s", mode, exitCode, command)
	env.Sessions.Append(id, header)
	for _, line := range outputLines(output) {
		env.Sessions.Append(id, "[pc-frida] "+line)
	}
	env.Audit.Log("frida.ingest_pc_result", map[string]any{"sessionId": id, "packageName": sess.PackageName, "pid": sess.PID, "mode": mode, "exitCode": exitCode, "outputBytes": len(output)})
	return map[string]any{"sessionId": id, "packageName": sess.PackageName, "pid": sess.PID, "mode": mode, "exitCode": exitCode, "ingestedLines": len(outputLines(output)) + 1}, nil
}

func fridaTemplateTraceMethod(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	className := strArg(args, "className", "")
	methodName := strArg(args, "methodName", "")
	if className == "" || methodName == "" {
		return nil, fmt.Errorf("className and methodName required")
	}
	script := GenerateTraceMethodScript(className, methodName)
	return map[string]any{"className": className, "methodName": methodName, "script": script}, nil
}

func fridaTemplateTraceClass(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	className := strArg(args, "className", "")
	if className == "" {
		return nil, fmt.Errorf("className required")
	}
	script := GenerateTraceClassScript(className)
	return map[string]any{"className": className, "script": script}, nil
}

func fridaPCSpawnCommand(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	scriptName := strArg(args, "scriptName", "hook.js")
	if scriptName == "" {
		scriptName = "hook.js"
	}
	host := strArg(args, "host", "127.0.0.1:27042")
	if host == "" {
		host = "127.0.0.1:27042"
	}
	return map[string]any{
		"packageName": pkg,
		"scriptName":  scriptName,
		"mode":        "pc-spawn-early-injection",
		"commands": []string{
			"# Save your Frida JS as " + scriptName + " on the PC",
			"# Option A: use USB device from PC",
			fmt.Sprintf("frida -U -f %s -l %s", pkg, scriptName),
			"# Option B: use adb forward from PC",
			"adb forward tcp:27042 tcp:27042",
			fmt.Sprintf("frida -H %s -f %s -l %s", host, pkg, scriptName),
		},
		"notes": []string{
			"Spawn mode starts the target package through Frida, so the script is loaded before most app code runs.",
			"Use this for early root/debugger/frida detection in Application/attachBaseContext/onCreate.",
			"Make sure frida-server is running on the Android device first.",
			"Current frida-tools resumes spawned apps by default. If your local Frida version pauses the app, resume it from the Frida REPL.",
		},
	}, nil
}

func GenerateTraceMethodScript(className, methodName string) string {
	cn, _ := json.Marshal(className)
	mn, _ := json.Marshal(methodName)
	return fmt.Sprintf(`'use strict';
if (Java.available) {
  Java.perform(function () {
    const className = %s;
    const methodName = %s;
    try {
      const C = Java.use(className);
      if (!C[methodName]) { console.log('[trace] method not found: ' + className + '.' + methodName); return; }
      C[methodName].overloads.forEach(function (ov, idx) {
        ov.implementation = function () {
          const args = [];
          for (let i = 0; i < arguments.length; i++) {
            try { args.push(String(arguments[i])); } catch (e) { args.push('<arg err ' + e + '>'); }
          }
          console.log('[trace] enter ' + className + '.' + methodName + '#' + idx + '(' + args.join(', ') + ')');
          const ret = ov.apply(this, arguments);
          try { console.log('[trace] leave ' + className + '.' + methodName + '#' + idx + ' => ' + ret); } catch (e) {}
          return ret;
        };
      });
      console.log('[trace] installed ' + className + '.' + methodName);
    } catch (e) { console.log('[trace] install failed: ' + e.stack); }
  });
} else {
  console.log('[trace] Java runtime is not available');
}
`, string(cn), string(mn))
}

func GenerateTraceClassScript(className string) string {
	cn, _ := json.Marshal(className)
	return fmt.Sprintf(`'use strict';
if (Java.available) {
  Java.perform(function () {
    const className = %s;
    try {
      const C = Java.use(className);
      const seen = {};
      C.class.getDeclaredMethods().forEach(function (m) {
        const name = String(m.getName());
        if (seen[name] || !C[name]) return;
        seen[name] = true;
        C[name].overloads.forEach(function (ov, idx) {
          ov.implementation = function () {
            const args = [];
            for (let i = 0; i < arguments.length; i++) {
              try { args.push(String(arguments[i])); } catch (e) { args.push('<arg err ' + e + '>'); }
            }
            console.log('[trace-class] enter ' + className + '.' + name + '#' + idx + '(' + args.join(', ') + ')');
            const ret = ov.apply(this, arguments);
            try { console.log('[trace-class] leave ' + className + '.' + name + '#' + idx + ' => ' + ret); } catch (e) {}
            return ret;
          };
        });
      });
      console.log('[trace-class] installed for ' + className);
    } catch (e) { console.log('[trace-class] install failed: ' + e.stack); }
  });
} else {
  console.log('[trace-class] Java runtime is not available');
}
`, string(cn))
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func execCommandNoWait(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeScriptForPackage(env *server.Env, packageName, prefix, script string) (string, error) {
	p := filepath.Join(env.Config.WorkspaceDir, "frida", safety.SafeName(packageName), safety.SafeName(prefix)+"-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".js")
	return p, writeTextFile(p, script)
}
