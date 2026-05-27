package tools

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"android-sec-mcp/daemon/caseflow"
	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func registerCase(reg *server.Registry) {
	reg.Register(server.Tool{Name: "case.create", Description: "Create a new case directory under the workspace.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "caseName": server.StringProp("Optional case name")}, []string{"packageName"}), Handler: caseCreate})
	reg.Register(server.Tool{Name: "case.run_basic_recon", Description: "Run minimal recon: device info, APK copy, dumpsys package, launch, screenshot, UI dump, logcat, report.md.", Risk: "medium", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "caseName": server.StringProp("Optional case name")}, []string{"packageName"}), Handler: caseRunBasicRecon})
	reg.Register(server.Tool{Name: "case.run_login_analysis", Description: "Run login analysis workflow with observation-only Frida hooks and optional target-scoped CTF Bypass Mode. Requires confirm=true.", Risk: "high", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "classNames": server.StringArrayProp("Java class names to observe"), "methodNames": server.StringArrayProp("Method names to observe"), "confirm": server.BoolProp("Required true"), "enableBypass": server.BoolProp("Enable CTF Bypass Mode if allowed"), "bypassProfiles": server.StringArrayProp("Bypass profile names"), "waitSeconds": server.IntProp("Message collection wait seconds"), "caseName": server.StringProp("Optional case name")}, []string{"packageName", "confirm"}), Handler: caseRunLoginAnalysis})
	reg.Register(server.Tool{Name: "case.export_report", Description: "Zip a case directory for export.", InputSchema: server.ObjectSchema(map[string]any{"caseDir": server.StringProp("Case directory path")}, []string{"caseDir"}), Handler: caseExportReport})
	reg.Register(server.Tool{Name: "case.get_report", Description: "Read report.md from a case directory or explicit reportPath.", InputSchema: server.ObjectSchema(map[string]any{"caseDir": server.StringProp("Case directory"), "reportPath": server.StringProp("Report path")}, nil), Handler: caseGetReport})
}

func caseCreate(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	c, err := caseflow.NewCase(env.Config.WorkspaceDir, pkg, strArg(args, "caseName", ""))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func caseRunBasicRecon(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	return caseflow.RunBasicRecon(ctx, env, caseflow.BasicReconInput{PackageName: pkg, CaseName: strArg(args, "caseName", "")})
}

func caseRunLoginAnalysis(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	in := caseflow.LoginAnalysisInput{PackageName: pkg, ClassNames: stringSliceArg(args, "classNames"), MethodNames: stringSliceArg(args, "methodNames"), Confirm: boolArg(args, "confirm", false), EnableBypass: boolArg(args, "enableBypass", false), BypassProfiles: stringSliceArg(args, "bypassProfiles"), WaitSeconds: intArg(args, "waitSeconds", 5), CaseName: strArg(args, "caseName", "")}
	return caseflow.RunLoginAnalysis(ctx, env, in)
}

func caseGetReport(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	path := strArg(args, "reportPath", "")
	if path == "" {
		caseDir := strArg(args, "caseDir", "")
		if caseDir == "" {
			return nil, fmt.Errorf("caseDir or reportPath required")
		}
		path = filepath.Join(caseDir, "report.md")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return map[string]any{"reportPath": path, "markdown": string(b)}, nil
}

func caseExportReport(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	caseDir := strArg(args, "caseDir", "")
	if caseDir == "" {
		return nil, fmt.Errorf("caseDir required")
	}
	if !strings.HasPrefix(filepath.Clean(caseDir), filepath.Clean(env.Config.WorkspaceDir)) {
		return nil, fmt.Errorf("caseDir must be under workspace")
	}
	out := filepath.Join(caseDir, safety.SafeName(filepath.Base(caseDir))+".zip")
	if err := zipDir(caseDir, out); err != nil {
		return nil, err
	}
	return map[string]any{"caseDir": caseDir, "zipPath": out}, nil
}

func zipDir(root, out string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if path == out {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
}
