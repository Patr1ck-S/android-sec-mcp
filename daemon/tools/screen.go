package tools

import (
	"context"
	"path/filepath"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func registerScreen(reg *server.Registry) {
	reg.Register(server.Tool{Name: "screen.screenshot", Description: "Capture screen as PNG to a device path under workspace by default.", InputSchema: server.ObjectSchema(map[string]any{"path": server.StringProp("Output PNG path on device")}, nil), Handler: screenScreenshot})
}

func screenScreenshot(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	path := strArg(args, "path", "")
	if path == "" {
		path = filepath.Join(env.Config.WorkspaceDir, "screens", safety.SafeName(time.Now().Format("20060102-150405"))+".png")
	}
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 15*time.Second, "screencap", "-p", path)
	return map[string]any{"path": path, "result": commandJSON(r)}, nil
}
