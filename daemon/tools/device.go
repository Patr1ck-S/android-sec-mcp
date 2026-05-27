package tools

import (
	"context"
	"strings"
	"time"

	"android-sec-mcp/daemon/server"
)

func registerDevice(reg *server.Registry) {
	reg.Register(server.Tool{Name: "device.info", Description: "Collect Android device identity, build and root daemon information.", InputSchema: server.ObjectSchema(nil, nil), Handler: deviceInfo})
	reg.Register(server.Tool{Name: "device.props", Description: "Return getprop values, optionally filtered by substring.", InputSchema: server.ObjectSchema(map[string]any{"filter": server.StringProp("Optional substring filter")}, nil), Handler: deviceProps})
	reg.Register(server.Tool{Name: "device.battery", Description: "Return dumpsys battery output.", InputSchema: server.ObjectSchema(nil, nil), Handler: deviceBattery})
	reg.Register(server.Tool{Name: "device.screen_size", Description: "Return wm size and density.", InputSchema: server.ObjectSchema(nil, nil), Handler: deviceScreenSize})
}

func getProp(ctx context.Context, env *server.Env, key string) string {
	r := env.Exec(ctx, 5*time.Second, "getprop", key)
	return strings.TrimSpace(r.Stdout)
}

func deviceInfo(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	props := map[string]string{}
	for _, k := range []string{"ro.product.brand", "ro.product.manufacturer", "ro.product.model", "ro.product.device", "ro.build.version.release", "ro.build.version.sdk", "ro.build.fingerprint", "ro.debuggable", "ro.secure", "ro.serialno"} {
		props[k] = getProp(ctx, env, k)
	}
	id := env.Exec(ctx, 5*time.Second, "id")
	uname := env.Exec(ctx, 5*time.Second, "uname", "-a")
	return map[string]any{"version": env.Version, "props": props, "id": strings.TrimSpace(id.Stdout), "uname": strings.TrimSpace(uname.Stdout), "workspace": env.Config.WorkspaceDir, "ctfBypassEnabled": env.Config.CTFBypassEnabled}, nil
}

func deviceProps(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	filter := strings.ToLower(strArg(args, "filter", ""))
	r := env.Exec(ctx, 10*time.Second, "getprop")
	lines := outputLines(r.Stdout)
	out := []string{}
	for _, l := range lines {
		if filter == "" || strings.Contains(strings.ToLower(l), filter) {
			out = append(out, l)
		}
	}
	return map[string]any{"filter": filter, "props": out, "rawExitCode": r.ExitCode}, nil
}

func deviceBattery(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	r := env.Exec(ctx, 10*time.Second, "dumpsys", "battery")
	parsed := map[string]string{}
	for _, l := range outputLines(r.Stdout) {
		if parts := strings.SplitN(strings.TrimSpace(l), ":", 2); len(parts) == 2 {
			parsed[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return map[string]any{"parsed": parsed, "raw": r.Stdout, "exitCode": r.ExitCode, "stderr": r.Stderr}, nil
}

func deviceScreenSize(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	size := env.Exec(ctx, 5*time.Second, "wm", "size")
	density := env.Exec(ctx, 5*time.Second, "wm", "density")
	return map[string]any{"size": strings.TrimSpace(size.Stdout), "density": strings.TrimSpace(density.Stdout), "raw": map[string]any{"size": commandJSON(size), "density": commandJSON(density)}}, nil
}
