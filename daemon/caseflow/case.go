package caseflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

type Case struct {
	ID          string    `json:"id"`
	PackageName string    `json:"packageName"`
	Root        string    `json:"root"`
	CreatedAt   time.Time `json:"createdAt"`
}

type BasicReconInput struct {
	PackageName string `json:"packageName"`
	CaseName    string `json:"caseName,omitempty"`
}

type LoginAnalysisInput struct {
	PackageName    string   `json:"packageName"`
	ClassNames     []string `json:"classNames,omitempty"`
	MethodNames    []string `json:"methodNames,omitempty"`
	Confirm        bool     `json:"confirm"`
	EnableBypass   bool     `json:"enableBypass,omitempty"`
	BypassProfiles []string `json:"bypassProfiles,omitempty"`
	WaitSeconds    int      `json:"waitSeconds,omitempty"`
	CaseName       string   `json:"caseName,omitempty"`
}

type RunSummary struct {
	CaseDir    string         `json:"caseDir"`
	ReportPath string         `json:"reportPath"`
	Summary    map[string]any `json:"summary"`
}

func NewCase(workspace, packageName, caseName string) (*Case, error) {
	if err := safety.ValidatePackageName(packageName); err != nil {
		return nil, err
	}
	ts := time.Now().Format("20060102-150405")
	name := safety.SafeName(caseName)
	if caseName == "" {
		name = safety.SafeName(packageName)
	}
	id := ts + "-" + name
	root := filepath.Join(workspace, id)
	for _, d := range []string{"apk", "manifest", "components", "screen", "ui", "logcat", "frida", "bypass"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0700); err != nil {
			return nil, err
		}
	}
	c := &Case{ID: id, PackageName: packageName, Root: root, CreatedAt: time.Now().UTC()}
	_ = WriteJSON(filepath.Join(root, "case.json"), c)
	return c, nil
}

func WriteJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

func WriteText(path, s string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(s), 0600)
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

func outputLines(s string) []string {
	parts := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	out := []string{}
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

func pmPaths(ctx context.Context, env *server.Env, pkg string) ([]string, error) {
	r := env.Exec(ctx, 20*time.Second, "pm", "path", pkg)
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("pm path %s failed: %s", pkg, strings.TrimSpace(r.Stdout+r.Stderr))
	}
	paths := []string{}
	for _, l := range outputLines(r.Stdout) {
		l = strings.TrimSpace(strings.TrimPrefix(l, "package:"))
		if l != "" {
			paths = append(paths, l)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no APK paths for %s", pkg)
	}
	return paths, nil
}

func pidByPackage(ctx context.Context, env *server.Env, pkg string) int {
	r := env.Exec(ctx, 5*time.Second, "pidof", pkg)
	if r.ExitCode == 0 {
		f := strings.Fields(r.Stdout)
		if len(f) > 0 {
			pid, _ := strconv.Atoi(f[0])
			return pid
		}
	}
	return 0
}

func currentActivity(ctx context.Context, env *server.Env) map[string]string {
	r := env.Exec(ctx, 10*time.Second, "dumpsys", "window")
	text := r.Stdout
	pats := []string{`mCurrentFocus=Window\{[^ ]+ [^ ]+ ([^}]+)\}`, `topResumedActivity=.* ([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)`, `mFocusedApp=.* ([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)`}
	comp := ""
	for _, p := range pats {
		if m := regexp.MustCompile(p).FindStringSubmatch(text); len(m) > 1 {
			comp = m[1]
			break
		}
	}
	pkg := ""
	if i := strings.Index(comp, "/"); i > 0 {
		pkg = comp[:i]
	}
	return map[string]string{"packageName": pkg, "component": comp}
}

func copyAPKs(ctx context.Context, env *server.Env, c *Case) ([]string, error) {
	paths, err := pmPaths(ctx, env, c.PackageName)
	if err != nil {
		return nil, err
	}
	copied := []string{}
	for i, src := range paths {
		name := "base.apk"
		if i > 0 {
			name = fmt.Sprintf("split_%d.apk", i)
		}
		dst := filepath.Join(c.Root, "apk", name)
		if err := copyFile(src, dst); err != nil {
			return copied, err
		}
		copied = append(copied, dst)
	}
	return copied, nil
}

func commandMap(r server.CommandResult) map[string]any {
	return map[string]any{"command": r.Command, "args": r.Args, "exitCode": r.ExitCode, "stdout": r.Stdout, "stderr": r.Stderr, "timedOut": r.TimedOut, "duration": r.Duration}
}
