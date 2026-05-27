package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func RegisterAll(reg *server.Registry) {
	registerDevice(reg)
	registerApp(reg)
	registerActivity(reg)
	registerScreen(reg)
	registerUI(reg)
	registerLogcat(reg)
	registerFrida(reg)
	registerCase(reg)
	registerCTF(reg)
}

func strArg(args map[string]any, key string, def string) string {
	if v, ok := args[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		case fmt.Stringer:
			return t.String()
		default:
			return fmt.Sprint(t)
		}
	}
	return def
}
func boolArg(args map[string]any, key string, def bool) bool {
	if v, ok := args[key]; ok {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return t == "true" || t == "1" || strings.EqualFold(t, "yes")
		}
	}
	return def
}
func intArg(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case json.Number:
			i, _ := t.Int64()
			return int(i)
		case string:
			i, err := strconv.Atoi(t)
			if err == nil {
				return i
			}
		}
	}
	return def
}
func stringSliceArg(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := []string{}
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		parts := strings.Split(t, ",")
		out := []string{}
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{fmt.Sprint(t)}
	}
}

func requirePackage(args map[string]any) (string, error) {
	pkg := strings.TrimSpace(strArg(args, "packageName", ""))
	if err := safety.ValidatePackageName(pkg); err != nil {
		return "", err
	}
	return pkg, nil
}

func ensureDir(p string) error { return os.MkdirAll(p, 0700) }
func safeJoin(root string, elems ...string) (string, error) {
	p := filepath.Join(append([]string{root}, elems...)...)
	cleanRoot := filepath.Clean(root) + string(os.PathSeparator)
	cleanP := filepath.Clean(p)
	if cleanP != filepath.Clean(root) && !strings.HasPrefix(cleanP, cleanRoot) {
		return "", fmt.Errorf("path escapes root")
	}
	return cleanP, nil
}

func commandJSON(r server.CommandResult) map[string]any {
	return map[string]any{"command": r.Command, "args": r.Args, "exitCode": r.ExitCode, "stdout": r.Stdout, "stderr": r.Stderr, "timedOut": r.TimedOut, "duration": r.Duration}
}

func outputLines(s string) []string {
	raw := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	out := []string{}
	for _, l := range raw {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func parsePmPath(out string) []string {
	paths := []string{}
	for _, l := range outputLines(out) {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "package:") {
			l = strings.TrimPrefix(l, "package:")
		}
		if l != "" {
			paths = append(paths, l)
		}
	}
	return paths
}

func packageExists(ctx context.Context, env *server.Env, pkg string) bool {
	r := env.Exec(ctx, 10*time.Second, "pm", "path", pkg)
	return r.ExitCode == 0 && strings.Contains(r.Stdout, "package:")
}

func firstApkPath(ctx context.Context, env *server.Env, pkg string) (string, []string, error) {
	r := env.Exec(ctx, 15*time.Second, "pm", "path", pkg)
	if r.ExitCode != 0 {
		return "", nil, fmt.Errorf("pm path failed: %s", strings.TrimSpace(r.Stderr+r.Stdout))
	}
	paths := parsePmPath(r.Stdout)
	if len(paths) == 0 {
		return "", nil, fmt.Errorf("no APK path for %s", pkg)
	}
	return paths[0], paths, nil
}

func pidByPackage(ctx context.Context, env *server.Env, pkg string) (int, string) {
	r := env.Exec(ctx, 5*time.Second, "pidof", pkg)
	if r.ExitCode == 0 {
		fields := strings.Fields(r.Stdout)
		if len(fields) > 0 {
			if pid, err := strconv.Atoi(fields[0]); err == nil {
				return pid, r.Stdout
			}
		}
	}
	ps := env.Exec(ctx, 10*time.Second, "ps", "-A")
	re := regexp.MustCompile(`(?m)^\S+\s+(\d+)\s+.*\s` + regexp.QuoteMeta(pkg) + `$`)
	m := re.FindStringSubmatch(ps.Stdout)
	if len(m) >= 2 {
		pid, _ := strconv.Atoi(m[1])
		return pid, ps.Stdout
	}
	return 0, ps.Stdout
}

func currentActivity(ctx context.Context, env *server.Env) map[string]any {
	w := env.Exec(ctx, 10*time.Second, "dumpsys", "window")
	text := w.Stdout
	patterns := []string{`mCurrentFocus=Window\{[^ ]+ [^ ]+ ([^}]+)\}`, `mFocusedApp=.* ([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)`, `topResumedActivity=.* ([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)`}
	comp := ""
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			comp = m[1]
			break
		}
	}
	pkg := ""
	if i := strings.Index(comp, "/"); i > 0 {
		pkg = comp[:i]
	}
	return map[string]any{"packageName": pkg, "component": comp, "raw": trimLen(text, 12000)}
}

func trimLen(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...[truncated]"
}

func writeTextFile(path, data string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(data), 0600)
}
