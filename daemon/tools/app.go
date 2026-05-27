package tools

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func registerApp(reg *server.Registry) {
	pkgReq := []string{"packageName"}
	reg.Register(server.Tool{Name: "app.list_packages", Description: "List installed packages.", InputSchema: server.ObjectSchema(map[string]any{"includeSystem": server.BoolProp("Include system packages"), "user": server.StringProp("Optional Android user id")}, nil), Handler: appListPackages})
	reg.Register(server.Tool{Name: "app.find_package", Description: "Find packages by substring.", InputSchema: server.ObjectSchema(map[string]any{"query": server.StringProp("Package substring")}, []string{"query"}), Handler: appFindPackage})
	reg.Register(server.Tool{Name: "app.package_info", Description: "Return dumpsys package output for a package.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: appPackageInfo})
	reg.Register(server.Tool{Name: "app.path", Description: "Return APK paths for a package.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: appPath})
	reg.Register(server.Tool{Name: "app.pull_apk", Description: "Copy installed APK(s) into workspace or outputDir on device.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "outputDir": server.StringProp("Device output directory, default workspace/apks/package")}, pkgReq), Handler: appPullAPK})
	reg.Register(server.Tool{Name: "app.permissions", Description: "Extract package permission lines from dumpsys.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: appPermissions})
	reg.Register(server.Tool{Name: "app.activities", Description: "Enumerate activity component hints from dumpsys package.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: func(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
		return appComponents(ctx, env, args, "activity")
	}})
	reg.Register(server.Tool{Name: "app.services", Description: "Enumerate service component hints from dumpsys package.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: func(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
		return appComponents(ctx, env, args, "service")
	}})
	reg.Register(server.Tool{Name: "app.receivers", Description: "Enumerate receiver component hints from dumpsys package.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: func(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
		return appComponents(ctx, env, args, "receiver")
	}})
	reg.Register(server.Tool{Name: "app.providers", Description: "Enumerate provider component hints from dumpsys package.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: func(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
		return appComponents(ctx, env, args, "provider")
	}})
	reg.Register(server.Tool{Name: "app.exported_components", Description: "Return exported component hints parsed from dumpsys package.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: appExportedComponents})
	reg.Register(server.Tool{Name: "app.launch", Description: "Launch target app via monkey launcher intent.", Risk: "medium", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, pkgReq), Handler: appLaunch})
	reg.Register(server.Tool{Name: "app.force_stop", Description: "Force stop target app. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "confirm": server.BoolProp("Required true")}, append(pkgReq, "confirm")), Handler: appForceStop})
}

func appListPackages(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	cmdArgs := []string{"list", "packages"}
	if !boolArg(args, "includeSystem", true) {
		cmdArgs = append(cmdArgs, "-3")
	}
	if u := strArg(args, "user", ""); u != "" {
		cmdArgs = append(cmdArgs, "--user", u)
	}
	r := env.Exec(ctx, 20*time.Second, "pm", cmdArgs...)
	pkgs := []string{}
	for _, l := range outputLines(r.Stdout) {
		pkgs = append(pkgs, strings.TrimPrefix(l, "package:"))
	}
	sort.Strings(pkgs)
	return map[string]any{"packages": pkgs, "count": len(pkgs), "exitCode": r.ExitCode, "stderr": r.Stderr}, nil
}

func appFindPackage(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	q := strings.ToLower(strArg(args, "query", ""))
	if q == "" {
		return nil, fmt.Errorf("query is required")
	}
	res, _ := appListPackages(ctx, env, map[string]any{"includeSystem": true})
	all := res.(map[string]any)["packages"].([]string)
	matches := []string{}
	for _, p := range all {
		if strings.Contains(strings.ToLower(p), q) {
			matches = append(matches, p)
		}
	}
	return map[string]any{"query": q, "matches": matches, "count": len(matches)}, nil
}

func appPackageInfo(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 30*time.Second, "dumpsys", "package", pkg)
	return map[string]any{"packageName": pkg, "raw": r.Stdout, "exitCode": r.ExitCode, "stderr": r.Stderr}, nil
}

func appPath(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	_, paths, err := firstApkPath(ctx, env, pkg)
	if err != nil {
		return nil, err
	}
	return map[string]any{"packageName": pkg, "paths": paths}, nil
}

func appPullAPK(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	_, paths, err := firstApkPath(ctx, env, pkg)
	if err != nil {
		return nil, err
	}
	outDir := strArg(args, "outputDir", "")
	if outDir == "" {
		outDir = filepath.Join(env.Config.WorkspaceDir, "apks", safety.SafeName(pkg))
	}
	if err := ensureDir(outDir); err != nil {
		return nil, err
	}
	copied := []string{}
	for i, src := range paths {
		name := "base.apk"
		if i > 0 {
			name = fmt.Sprintf("split_%d.apk", i)
		}
		dst := filepath.Join(outDir, name)
		if err := copyFile(src, dst); err != nil {
			return nil, fmt.Errorf("copy %s: %w", src, err)
		}
		copied = append(copied, dst)
	}
	return map[string]any{"packageName": pkg, "sourcePaths": paths, "copied": copied, "outputDir": outDir}, nil
}

func appPermissions(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 30*time.Second, "dumpsys", "package", pkg)
	lines := []string{}
	inPerm := false
	for _, l := range outputLines(r.Stdout) {
		tl := strings.TrimSpace(l)
		low := strings.ToLower(tl)
		if strings.Contains(low, "permission") {
			inPerm = true
		}
		if inPerm && (strings.Contains(low, "permission") || strings.HasPrefix(tl, "android.permission.") || strings.Contains(tl, "granted=")) {
			lines = append(lines, tl)
		}
		if inPerm && strings.HasSuffix(tl, ":") && !strings.Contains(low, "permission") {
			inPerm = false
		}
	}
	return map[string]any{"packageName": pkg, "permissions": lines, "rawExitCode": r.ExitCode}, nil
}

func appComponents(ctx context.Context, env *server.Env, args map[string]any, kind string) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 30*time.Second, "dumpsys", "package", pkg)
	comps := parseComponents(r.Stdout, pkg, kind)
	return map[string]any{"packageName": pkg, "kind": kind, "components": comps, "count": len(comps), "note": "Parsed heuristically from dumpsys package. Keep raw package_info for authoritative details."}, nil
}

func appExportedComponents(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 30*time.Second, "dumpsys", "package", pkg)
	all := map[string][]string{}
	for _, kind := range []string{"activity", "service", "receiver", "provider"} {
		all[kind] = parseExported(r.Stdout, pkg, kind)
	}
	return map[string]any{"packageName": pkg, "exported": all, "note": "Heuristic parser: verifies lines near components with exported=true."}, nil
}

func appLaunch(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 20*time.Second, "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1")
	return map[string]any{"packageName": pkg, "result": commandJSON(r)}, nil
}

func appForceStop(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	if err := safety.RequireConfirm(boolArg(args, "confirm", false), "app.force_stop"); err != nil {
		return nil, err
	}
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 10*time.Second, "am", "force-stop", pkg)
	return map[string]any{"packageName": pkg, "result": commandJSON(r)}, nil
}

func parseComponents(raw, pkg, kind string) []string {
	sectionNames := map[string][]string{
		"activity": {"Activity Resolver Table", "Activities:"},
		"service":  {"Service Resolver Table", "Services:"},
		"receiver": {"Receiver Resolver Table", "Receivers:"},
		"provider": {"Provider Resolver Table", "Providers:"},
	}
	lines := strings.Split(raw, "\n")
	in := false
	seen := map[string]bool{}
	re := regexp.MustCompile(regexp.QuoteMeta(pkg) + `/[A-Za-z0-9_.$]+`)
	for _, l := range lines {
		tl := strings.TrimSpace(l)
		for _, sn := range sectionNames[kind] {
			if strings.Contains(tl, sn) {
				in = true
			}
		}
		if in && strings.HasSuffix(tl, ":") && !containsAny(tl, sectionNames[kind]) && (strings.Contains(tl, "Resolver Table") || strings.Contains(tl, "Permissions") || strings.Contains(tl, "Packages:")) {
			in = false
		}
		if !in && !strings.Contains(l, pkg+"/") {
			continue
		}
		for _, m := range re.FindAllString(l, -1) {
			seen[m] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func parseExported(raw, pkg, kind string) []string {
	comps := parseComponents(raw, pkg, kind)
	out := []string{}
	for _, c := range comps {
		idx := strings.Index(raw, c)
		if idx < 0 {
			continue
		}
		end := idx + 1000
		if end > len(raw) {
			end = len(raw)
		}
		window := raw[idx:end]
		if strings.Contains(window, "exported=true") || strings.Contains(window, "exported: true") {
			out = append(out, c)
		}
	}
	return out
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
