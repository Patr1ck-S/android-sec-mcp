package caseflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func RunBasicRecon(ctx context.Context, env *server.Env, in BasicReconInput) (*RunSummary, error) {
	c, err := NewCase(env.Config.WorkspaceDir, in.PackageName, in.CaseName)
	if err != nil {
		return nil, err
	}
	device := collectDevice(ctx, env)
	apks, err := copyAPKs(ctx, env, c)
	if err != nil {
		return nil, err
	}
	dumpsys := env.Exec(ctx, 30*time.Second, "dumpsys", "package", in.PackageName)
	_ = WriteText(filepath.Join(c.Root, "manifest", "dumpsys_package.txt"), dumpsys.Stdout)
	_ = WriteJSON(filepath.Join(c.Root, "components", "package_raw_command.json"), commandMap(dumpsys))

	launch := env.Exec(ctx, 20*time.Second, "monkey", "-p", in.PackageName, "-c", "android.intent.category.LAUNCHER", "1")
	time.Sleep(1500 * time.Millisecond)
	shot := filepath.Join(c.Root, "screen", "recon.png")
	_ = env.Exec(ctx, 15*time.Second, "screencap", "-p", shot)
	xmlPath := filepath.Join(c.Root, "ui", "recon.xml")
	_ = env.Exec(ctx, 20*time.Second, "uiautomator", "dump", xmlPath)
	cur := currentActivity(ctx, env)
	pid := pidByPackage(ctx, env, in.PackageName)
	log := env.Exec(ctx, 20*time.Second, "logcat", "-d", "-v", "threadtime", "-t", "500")
	logPath := filepath.Join(c.Root, "logcat", "recon.log")
	_ = WriteText(logPath, log.Stdout)

	reportPath := filepath.Join(c.Root, "report.md")
	findings := []string{}
	if pid == 0 {
		findings = append(findings, "Target process PID was not found after launch; app may not have started or package has no launcher activity.")
	}
	if launch.ExitCode != 0 {
		findings = append(findings, "App launch command returned non-zero exit code; inspect launch output.")
	}
	_ = GenerateReport(reportPath, ReportData{Title: "Android Basic Recon Report", Case: c, Device: device, APKPaths: apks, Current: cur, PID: pid, Screenshots: []string{shot}, UIXML: []string{xmlPath}, Logcat: outputLines(log.Stdout), Findings: findings})
	return &RunSummary{CaseDir: c.Root, ReportPath: reportPath, Summary: map[string]any{"packageName": in.PackageName, "pid": pid, "currentActivity": cur, "apkCount": len(apks), "logcat": logPath}}, nil
}

func RunLoginAnalysis(ctx context.Context, env *server.Env, in LoginAnalysisInput) (*RunSummary, error) {
	if err := safety.RequireConfirm(in.Confirm, "case.run_login_analysis"); err != nil {
		return nil, err
	}
	if in.WaitSeconds <= 0 {
		in.WaitSeconds = 5
	}
	if in.WaitSeconds > 60 {
		in.WaitSeconds = 60
	}
	c, err := NewCase(env.Config.WorkspaceDir, in.PackageName, in.CaseName)
	if err != nil {
		return nil, err
	}
	env.Audit.Log("case.login_analysis.start", map[string]any{"caseDir": c.Root, "packageName": in.PackageName, "enableBypass": in.EnableBypass, "bypassProfiles": in.BypassProfiles})

	device := collectDevice(ctx, env)
	paths, err := pmPaths(ctx, env, in.PackageName)
	if err != nil {
		return nil, err
	}
	_ = WriteJSON(filepath.Join(c.Root, "apk", "source_paths.json"), paths)
	apks, err := copyAPKs(ctx, env, c)
	if err != nil {
		return nil, err
	}
	baseAPK := apks[0]

	dumpsys := env.Exec(ctx, 30*time.Second, "dumpsys", "package", in.PackageName)
	_ = WriteText(filepath.Join(c.Root, "manifest", "dumpsys_package.txt"), dumpsys.Stdout)
	_ = WriteJSON(filepath.Join(c.Root, "manifest", "dumpsys_package_command.json"), commandMap(dumpsys))
	_ = WriteJSON(filepath.Join(c.Root, "components", "heuristic_components.json"), heuristicComponents(dumpsys.Stdout, in.PackageName))

	launch := env.Exec(ctx, 20*time.Second, "monkey", "-p", in.PackageName, "-c", "android.intent.category.LAUNCHER", "1")
	_ = WriteJSON(filepath.Join(c.Root, "launch.json"), commandMap(launch))
	time.Sleep(2 * time.Second)

	shotBefore := filepath.Join(c.Root, "screen", "before.png")
	_ = env.Exec(ctx, 15*time.Second, "screencap", "-p", shotBefore)
	xmlBefore := filepath.Join(c.Root, "ui", "before.xml")
	_ = env.Exec(ctx, 20*time.Second, "uiautomator", "dump", xmlBefore)
	cur := currentActivity(ctx, env)
	pid := pidByPackage(ctx, env, in.PackageName)
	if pid == 0 {
		return nil, fmt.Errorf("target PID not found for %s after launch", in.PackageName)
	}

	_ = env.Exec(ctx, 10*time.Second, "logcat", "-c")
	time.Sleep(500 * time.Millisecond)
	initialLog := env.Exec(ctx, 20*time.Second, "logcat", "-d", "-v", "threadtime", "-t", "500")
	_ = WriteText(filepath.Join(c.Root, "logcat", "initial.log"), initialLog.Stdout)

	fridaStatus := checkFrida(ctx, env)
	if !fridaStatus.Running {
		if fridaStatus.ServerExists {
			cmd := execNoWait(env.Config.FridaServerPath)
			if err := cmd.Start(); err == nil {
				env.Audit.Log("frida.server_start", map[string]any{"by": "case.run_login_analysis", "pid": cmd.Process.Pid})
				time.Sleep(800 * time.Millisecond)
				fridaStatus = checkFrida(ctx, env)
			}
		}
	}

	sess := env.Sessions.New(in.PackageName, pid)
	obsScript := buildObservationScript(in.ClassNames, in.MethodNames)
	obsPath := filepath.Join(c.Root, "frida", "login_observation.js")
	_ = WriteText(obsPath, obsScript)
	sess, _ = env.StartFridaScript(ctx, sess, obsPath)
	env.Audit.Log("frida.load_script", map[string]any{"by": "case.run_login_analysis", "sessionId": sess.ID, "packageName": in.PackageName, "pid": pid, "scriptPath": obsPath, "loaded": sess.Loaded})
	time.Sleep(time.Duration(in.WaitSeconds) * time.Second)
	sessNow, _ := env.Sessions.Get(sess.ID)
	fridaMessages := []string{}
	if sessNow != nil {
		fridaMessages = append(fridaMessages, sessNow.Messages...)
	}

	bypassInfo := map[string]any{}
	if in.EnableBypass {
		bi, err := runBypassProfiles(ctx, env, c, in.PackageName, baseAPK, pid, in.BypassProfiles, in.Confirm)
		if err != nil {
			bypassInfo["error"] = err.Error()
			env.Audit.Log("ctf.bypass.error", map[string]any{"packageName": in.PackageName, "error": err.Error()})
		} else {
			bypassInfo = bi
		}
	}

	finalLog := env.Exec(ctx, 20*time.Second, "logcat", "-d", "-v", "threadtime", "-t", "1000")
	finalLogPath := filepath.Join(c.Root, "logcat", "final.log")
	_ = WriteText(finalLogPath, finalLog.Stdout)
	shotAfter := filepath.Join(c.Root, "screen", "after.png")
	_ = env.Exec(ctx, 15*time.Second, "screencap", "-p", shotAfter)

	reportPath := filepath.Join(c.Root, "report.md")
	findings := []string{}
	if !fridaStatus.Running {
		findings = append(findings, "frida-server was not confirmed running; observation script may only be generated, not loaded.")
	}
	if sess != nil && !sess.Loaded {
		findings = append(findings, "Frida CLI path is not configured or failed; script saved for manual loading.")
	}
	_ = GenerateReport(reportPath, ReportData{Title: "Android Login Analysis Report", Case: c, Device: device, APKPaths: apks, Current: cur, PID: pid, Screenshots: []string{shotBefore, shotAfter}, UIXML: []string{xmlBefore}, Logcat: outputLines(finalLog.Stdout), FridaScript: obsPath, FridaSession: sess, FridaMessages: fridaMessages, Bypass: bypassInfo, Findings: findings})
	env.Audit.Log("case.login_analysis.finish", map[string]any{"caseDir": c.Root, "reportPath": reportPath, "packageName": in.PackageName})
	summary := map[string]any{"packageName": in.PackageName, "pid": pid, "currentActivity": cur, "fridaSessionId": sess.ID, "fridaLoaded": sess.Loaded, "bypass": bypassInfo}
	if sess != nil && sess.PCMode != nil {
		summary["fridaPCMode"] = sess.PCMode
	}
	return &RunSummary{CaseDir: c.Root, ReportPath: reportPath, Summary: summary}, nil
}

type fridaState struct {
	Running       bool   `json:"running"`
	PID           string `json:"pid"`
	ServerExists  bool   `json:"serverExists"`
	CliConfigured bool   `json:"cliConfigured"`
}

func checkFrida(ctx context.Context, env *server.Env) fridaState {
	r := env.Exec(ctx, 5*time.Second, "pidof", "frida-server")
	return fridaState{Running: r.ExitCode == 0, PID: strings.TrimSpace(r.Stdout), ServerExists: fileExists(env.Config.FridaServerPath), CliConfigured: env.Config.FridaCliPath != ""}
}

func collectDevice(ctx context.Context, env *server.Env) map[string]any {
	props := map[string]string{}
	for _, k := range []string{"ro.product.brand", "ro.product.model", "ro.product.device", "ro.build.version.release", "ro.build.version.sdk", "ro.build.fingerprint"} {
		props[k] = strings.TrimSpace(env.Exec(ctx, 5*time.Second, "getprop", k).Stdout)
	}
	return map[string]any{"props": props, "id": strings.TrimSpace(env.Exec(ctx, 5*time.Second, "id").Stdout), "uname": strings.TrimSpace(env.Exec(ctx, 5*time.Second, "uname", "-a").Stdout)}
}

func buildObservationScript(classes, methods []string) string {
	var b strings.Builder
	b.WriteString("'use strict';\n")
	b.WriteString("// Observation-only login analysis hooks generated by android-sec-mcp.\n")
	b.WriteString("function log(x) { console.log('[login-analysis] ' + x); }\n")
	b.WriteString("function hookMethod(className, methodName) {\n")
	b.WriteString("  try { const C = Java.use(className); if (!C[methodName]) { log('missing ' + className + '.' + methodName); return; }\n")
	b.WriteString("    C[methodName].overloads.forEach(function(ov, idx) { ov.implementation = function() {\n")
	b.WriteString("      const args = []; for (let i=0;i<arguments.length;i++) { try { args.push(String(arguments[i])); } catch(e) { args.push('<err>'); } }\n")
	b.WriteString("      log('enter ' + className + '.' + methodName + '#' + idx + '(' + args.join(', ') + ')');\n")
	b.WriteString("      const ret = ov.apply(this, arguments); try { log('leave ' + className + '.' + methodName + '#' + idx + ' => ' + ret); } catch(e) {} return ret;\n")
	b.WriteString("    }; }); log('hooked ' + className + '.' + methodName); } catch(e) { log('hook failed ' + className + '.' + methodName + ': ' + e); }\n")
	b.WriteString("}\n")
	b.WriteString("function hookClass(className) { try { const C = Java.use(className); const seen = {}; C.class.getDeclaredMethods().forEach(function(m) { const n = String(m.getName()); if (seen[n] || !C[n]) return; seen[n]=true; hookMethod(className, n); }); } catch(e) { log('class hook failed ' + className + ': ' + e); } }\n")
	b.WriteString("if (Java.available) { Java.perform(function() {\n")
	if len(classes) == 0 && len(methods) == 0 {
		b.WriteString("  log('no classNames/methodNames provided; installing common login observers');\n")
		classes = []string{"android.widget.EditText", "android.widget.TextView"}
		methods = []string{"setText", "getText", "performClick"}
	}
	for _, c := range classes {
		if len(methods) == 0 {
			b.WriteString("  hookClass(" + quote(c) + ");\n")
		} else {
			for _, m := range methods {
				b.WriteString("  hookMethod(" + quote(c) + ", " + quote(m) + ");\n")
			}
		}
	}
	b.WriteString("}); } else { log('Java runtime not available'); }\n")
	return b.String()
}

func runBypassProfiles(ctx context.Context, env *server.Env, c *Case, pkg, baseAPK string, pid int, names []string, confirm bool) (map[string]any, error) {
	if !env.Config.CTFBypassEnabled {
		return nil, fmt.Errorf("ctfBypassEnabled=false")
	}
	if err := safety.RequireConfirm(confirm, "CTF Bypass Mode"); err != nil {
		return nil, err
	}
	if err := safety.EnsureAllowedPackage(pkg, env.Config.AllowedBypassPackages); err != nil {
		return nil, err
	}
	points, _ := safety.ScanAPK(baseAPK)
	allProfiles, _ := safety.ListProfiles(env.Config.BypassProfilesDir)
	plan := safety.GeneratePlan(pkg, points, allProfiles)
	if len(names) == 0 {
		names = plan.SuggestedProfiles
	}
	profiles := []safety.BypassProfile{}
	profilePaths := []string{}
	for _, n := range names {
		p, path, err := safety.LoadProfile(env.Config.BypassProfilesDir, n)
		if err != nil {
			return nil, err
		}
		if p.RequiresConfirm && !confirm {
			return nil, fmt.Errorf("profile %s requires confirm=true", p.Name)
		}
		profiles = append(profiles, *p)
		profilePaths = append(profilePaths, path)
	}
	script := safety.GenerateFridaScript(pkg, profiles)
	scriptPath := filepath.Join(c.Root, "bypass", "runtime_profiles.js")
	_ = WriteText(scriptPath, script)
	sess := env.Sessions.New(pkg, pid)
	loaded, _ := env.StartFridaScript(ctx, sess, scriptPath)
	info := map[string]any{"enabled": true, "packageName": pkg, "scope": "target-package-runtime", "detectionPoints": points, "classifications": plan.Classifications, "profiles": names, "profilePaths": profilePaths, "scriptPath": scriptPath, "loadTime": time.Now().UTC().Format(time.RFC3339), "session": loaded, "reverted": false, "revert": "runtime profile is reverted by detaching/stopping the Frida session"}
	_ = WriteJSON(filepath.Join(c.Root, "bypass", "bypass_info.json"), info)
	env.Audit.Log("ctf.bypass.apply_profile", map[string]any{"packageName": pkg, "caseDir": c.Root, "profiles": names, "scriptPath": scriptPath, "loaded": loaded != nil && loaded.Loaded})
	return info, nil
}

func heuristicComponents(raw, pkg string) map[string]any {
	kinds := []string{"Activity", "Service", "Receiver", "Provider"}
	out := map[string]any{}
	for _, k := range kinds {
		lines := []string{}
		for _, l := range outputLines(raw) {
			if strings.Contains(l, pkg+"/") && strings.Contains(strings.ToLower(l), strings.ToLower(k[:3])) {
				lines = append(lines, strings.TrimSpace(l))
			}
		}
		out[strings.ToLower(k)] = lines
	}
	return out
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

// local tiny wrappers avoid importing the tools package and creating a package cycle.
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
func execNoWait(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
