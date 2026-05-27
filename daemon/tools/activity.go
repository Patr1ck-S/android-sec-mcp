package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"android-sec-mcp/daemon/server"
)

func registerActivity(reg *server.Registry) {
	reg.Register(server.Tool{Name: "runtime.foreground_package", Description: "Return the current foreground package parsed from dumpsys window.", InputSchema: server.ObjectSchema(nil, nil), Handler: runtimeForegroundPackage})
	reg.Register(server.Tool{Name: "runtime.current_activity", Description: "Return the current focused/resumed Activity component.", InputSchema: server.ObjectSchema(nil, nil), Handler: runtimeCurrentActivity})
	reg.Register(server.Tool{Name: "runtime.pid_by_package", Description: "Return PID for a package using pidof/ps.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package")}, []string{"packageName"}), Handler: runtimePIDByPackage})
}

func runtimeForegroundPackage(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	ca := currentActivity(ctx, env)
	return map[string]any{"packageName": ca["packageName"], "component": ca["component"]}, nil
}

func runtimeCurrentActivity(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	return currentActivity(ctx, env), nil
}

func runtimePIDByPackage(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	pid, raw := pidByPackage(ctx, env, pkg)
	if pid == 0 {
		return map[string]any{"packageName": pkg, "pid": nil, "raw": trimLen(raw, 12000)}, nil
	}
	return map[string]any{"packageName": pkg, "pid": pid, "raw": strings.TrimSpace(raw)}, nil
}

func waitForPID(ctx context.Context, env *server.Env, pkg string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pid, _ := pidByPackage(ctx, env, pkg)
		if pid > 0 {
			return pid, nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return 0, fmt.Errorf("pid for %s not found within %s", pkg, timeout)
}
