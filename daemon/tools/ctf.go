package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func registerCTF(reg *server.Registry) {
	reg.Register(server.Tool{Name: "ctf.scan_detection_points", Description: "Scan target APK for root/debugger/emulator/frida/traffic-capture detection points using scored static rules plus native ELF import checks.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "apkPath": server.StringProp("Optional APK path")}, nil), Handler: ctfScanDetectionPoints})
	reg.Register(server.Tool{Name: "ctf.classify_protection", Description: "Classify root/debugger/emulator/frida/traffic-capture protection levels from scan results.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "apkPath": server.StringProp("Optional APK path")}, nil), Handler: ctfClassifyProtection})
	reg.Register(server.Tool{Name: "ctf.list_bypass_profiles", Description: "List JSON bypass profiles from /data/adb/android-sec-mcp/bypass-profiles/.", InputSchema: server.ObjectSchema(nil, nil), Handler: ctfListBypassProfiles})
	reg.Register(server.Tool{Name: "ctf.generate_bypass_plan", Description: "Generate a target-scoped CTF bypass plan without applying it.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "apkPath": server.StringProp("Optional APK path")}, []string{"packageName"}), Handler: ctfGenerateBypassPlan})
	reg.Register(server.Tool{Name: "ctf.apply_bypass_profile", Description: "Apply target-scoped Frida runtime bypass profiles. Requires ctfBypassEnabled=true, package allow-list, confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "profiles": server.StringArrayProp("Profile names"), "confirm": server.BoolProp("Required true")}, []string{"packageName", "profiles", "confirm"}), Handler: ctfApplyBypassProfile})
	reg.Register(server.Tool{Name: "ctf.revert_bypass_profile", Description: "Detach/stop runtime Frida profile session by sessionId. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"sessionId": server.StringProp("Session id"), "confirm": server.BoolProp("Required true")}, []string{"sessionId", "confirm"}), Handler: ctfRevertBypassProfile})
	reg.Register(server.Tool{Name: "ctf.run_target_with_profile", Description: "Launch target and apply bypass profile after PID appears. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "profiles": server.StringArrayProp("Profile names"), "confirm": server.BoolProp("Required true")}, []string{"packageName", "profiles", "confirm"}), Handler: ctfRunTargetWithProfile})
	reg.Register(server.Tool{Name: "ctf.export_bypass_report", Description: "Export a markdown CTF bypass report from scan/plan/profile data.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "caseDir": server.StringProp("Optional case dir")}, []string{"packageName"}), Handler: ctfExportBypassReport})
	reg.Register(server.Tool{Name: "ctf.prepare_debugger_bypass", Description: "Scan debugger-detection points, generate target-scoped anti-debug Frida JS, save it on Android, and return PC-side injection commands. Requires ctfBypassEnabled=true, allow-list, confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "apkPath": server.StringProp("Optional APK path"), "confirm": server.BoolProp("Required true")}, []string{"packageName", "confirm"}), Handler: ctfPrepareDebuggerBypass})
}

func ctfScanDetectionPoints(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	apk, pkg, err := resolveAPKForCTF(ctx, env, args)
	if err != nil {
		return nil, err
	}
	pts, err := safety.ScanAPK(apk)
	if err != nil {
		return nil, err
	}
	return map[string]any{"packageName": pkg, "apkPath": apk, "detectionPoints": pts, "count": len(pts)}, nil
}

func ctfClassifyProtection(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	scan, err := ctfScanDetectionPoints(ctx, env, args)
	if err != nil {
		return nil, err
	}
	pts := scan.(map[string]any)["detectionPoints"].([]safety.DetectionPoint)
	return map[string]any{"packageName": scan.(map[string]any)["packageName"], "apkPath": scan.(map[string]any)["apkPath"], "classifications": safety.Classify(pts), "detectionPoints": pts}, nil
}

func ctfListBypassProfiles(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	profiles, err := safety.ListProfiles(env.Config.BypassProfilesDir)
	if err != nil {
		return nil, err
	}
	return map[string]any{"profilesDir": env.Config.BypassProfilesDir, "profiles": profiles, "count": len(profiles), "ctfBypassEnabled": env.Config.CTFBypassEnabled, "allowedBypassPackages": env.Config.AllowedBypassPackages}, nil
}

func ctfGenerateBypassPlan(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	apk, pkg, err := resolveAPKForCTF(ctx, env, args)
	if err != nil {
		return nil, err
	}
	pts, err := safety.ScanAPK(apk)
	if err != nil {
		return nil, err
	}
	profiles, _ := safety.ListProfiles(env.Config.BypassProfilesDir)
	plan := safety.GeneratePlan(pkg, pts, profiles)
	return map[string]any{"apkPath": apk, "plan": plan}, nil
}

func ctfApplyBypassProfile(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if !env.Config.CTFBypassEnabled {
		return nil, fmt.Errorf("ctfBypassEnabled=false")
	}
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "ctf.apply_bypass_profile"); err != nil {
		return nil, err
	}
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	if err := safety.EnsureAllowedPackage(pkg, env.Config.AllowedBypassPackages); err != nil {
		return nil, err
	}
	profilesArg := stringSliceArg(args, "profiles")
	if len(profilesArg) == 0 {
		return nil, fmt.Errorf("profiles required")
	}
	pid, _ := pidByPackage(ctx, env, pkg)
	if pid == 0 {
		return nil, fmt.Errorf("target %s is not running; use app.launch or ctf.run_target_with_profile", pkg)
	}
	profiles := []safety.BypassProfile{}
	paths := []string{}
	for _, name := range profilesArg {
		prof, p, err := safety.LoadProfile(env.Config.BypassProfilesDir, name)
		if err != nil {
			return nil, err
		}
		if prof.RequiresConfirm && !boolArg(args, "confirm", false) {
			return nil, fmt.Errorf("profile %s requires confirm=true", prof.Name)
		}
		profiles = append(profiles, *prof)
		paths = append(paths, p)
	}
	script := safety.GenerateFridaScript(pkg, profiles)
	scriptPath, err := writeScriptForPackage(env, pkg, "ctf-bypass", script)
	if err != nil {
		return nil, err
	}
	sess := env.Sessions.New(pkg, pid)
	sess, err = env.StartFridaScript(ctx, sess, scriptPath)
	env.Audit.Log("ctf.bypass.apply_profile", map[string]any{"packageName": pkg, "pid": pid, "profiles": profilesArg, "profilePaths": paths, "scriptPath": scriptPath, "loaded": sess != nil && sess.Loaded, "error": errString(err)})
	if err != nil {
		return nil, err
	}
	return map[string]any{"packageName": pkg, "pid": pid, "profiles": profilesArg, "profilePaths": paths, "scriptPath": scriptPath, "session": sess, "scope": "target-package-runtime", "loadedAt": time.Now().UTC().Format(time.RFC3339), "reverted": false}, nil
}

func ctfRevertBypassProfile(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "ctf.revert_bypass_profile"); err != nil {
		return nil, err
	}
	id := strArg(args, "sessionId", "")
	ok := env.Sessions.Stop(id)
	env.Audit.Log("ctf.bypass.revert_profile", map[string]any{"sessionId": id, "stopped": ok})
	return map[string]any{"sessionId": id, "stopped": ok, "reverted": ok, "time": time.Now().UTC().Format(time.RFC3339)}, nil
}

func ctfRunTargetWithProfile(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "ctf.run_target_with_profile"); err != nil {
		return nil, err
	}
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	launch, _ := appLaunch(ctx, env, map[string]any{"packageName": pkg})
	deadline := time.Now().Add(10 * time.Second)
	var pid int
	for time.Now().Before(deadline) {
		pid, _ = pidByPackage(ctx, env, pkg)
		if pid > 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if pid == 0 {
		return map[string]any{"launch": launch, "error": "pid not found"}, nil
	}
	apply, err := ctfApplyBypassProfile(ctx, env, args)
	if err != nil {
		return nil, err
	}
	return map[string]any{"launch": launch, "apply": apply}, nil
}

func ctfExportBypassReport(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	caseDir := strArg(args, "caseDir", "")
	if caseDir == "" {
		caseDir = filepath.Join(env.Config.WorkspaceDir, "ctf-bypass-"+safety.SafeName(pkg)+"-"+time.Now().Format("20060102-150405"))
	}
	if err := ensureDir(caseDir); err != nil {
		return nil, err
	}
	planAny, err := ctfGenerateBypassPlan(ctx, env, map[string]any{"packageName": pkg})
	if err != nil {
		return nil, err
	}
	path := filepath.Join(caseDir, "bypass_report.md")
	md := "# CTF Bypass Mode Report\n\n" +
		"- Package: `" + pkg + "`\n" +
		"- Generated: `" + time.Now().UTC().Format(time.RFC3339) + "`\n" +
		"- Scope: target package only; no global device patching.\n" +
		"- Requirements to apply: `ctfBypassEnabled=true`, package in `allowedBypassPackages`, and `confirm=true`.\n\n" +
		"```json\n" + mustJSON(planAny) + "\n```\n"
	if err := writeTextFile(path, md); err != nil {
		return nil, err
	}
	env.Audit.Log("ctf.bypass.export_report", map[string]any{"packageName": pkg, "path": path})
	return map[string]any{"packageName": pkg, "reportPath": path}, nil
}

func ctfPrepareDebuggerBypass(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if !env.Config.CTFBypassEnabled {
		return nil, fmt.Errorf("ctfBypassEnabled=false")
	}
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "ctf.prepare_debugger_bypass"); err != nil {
		return nil, err
	}
	apk, pkg, err := resolveAPKForCTF(ctx, env, args)
	if err != nil {
		return nil, err
	}
	if err := safety.EnsureAllowedPackage(pkg, env.Config.AllowedBypassPackages); err != nil {
		return nil, err
	}
	points, err := safety.ScanAPK(apk)
	if err != nil {
		return nil, err
	}
	debugPoints := []safety.DetectionPoint{}
	for _, p := range points {
		if p.Protection == "debugger_detection" {
			debugPoints = append(debugPoints, p)
		}
	}
	script := safety.GenerateDebuggerBypassScript(pkg, debugPoints)
	scriptPath, err := writeScriptForPackage(env, pkg, "anti-debug-bypass", script)
	if err != nil {
		return nil, err
	}
	pid, _ := pidByPackage(ctx, env, pkg)
	sess := env.Sessions.New(pkg, pid)
	sess.ScriptPath = scriptPath
	sess.Loaded = false
	sess.Note = "pc-side anti-debug bypass prepared; export the generated JS with adb, then inject it from PC frida-tools"
	sess.PCMode = server.BuildPCMode(sess, scriptPath, sess.Note)
	env.Sessions.Put(sess)
	env.Audit.Log("ctf.prepare_debugger_bypass", map[string]any{"sessionId": sess.ID, "packageName": pkg, "pid": pid, "apkPath": apk, "debuggerPoints": len(debugPoints), "scriptPath": scriptPath})
	return map[string]any{
		"packageName":       pkg,
		"pid":               pid,
		"apkPath":           apk,
		"detectionPoints":   debugPoints,
		"classifications":   safety.Classify(debugPoints),
		"scriptPath":        scriptPath,
		"session":           sess,
		"pcMode":            sess.PCMode,
		"recommendedInject": "spawn",
		"notes": []string{
			"Generated script hooks android.os.Debug checks, TracerPid reads, libc.ptrace, and syscall(ptrace).",
			"Use spawn injection for checks in Application.attachBaseContext/onCreate.",
		},
	}, nil
}

func resolveAPKForCTF(ctx context.Context, env *server.Env, args map[string]any) (apk, pkg string, err error) {
	apk = strArg(args, "apkPath", "")
	pkg = strArg(args, "packageName", "")
	if apk != "" {
		return apk, pkg, nil
	}
	pkg, err = requirePackage(args)
	if err != nil {
		return "", "", err
	}
	base, paths, err := firstApkPath(ctx, env, pkg)
	_ = paths
	return base, pkg, err
}

func mustJSON(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
