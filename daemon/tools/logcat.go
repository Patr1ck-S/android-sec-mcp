package tools

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"android-sec-mcp/daemon/server"
)

func registerLogcat(reg *server.Registry) {
	reg.Register(server.Tool{Name: "logcat.clear", Description: "Clear logcat buffer.", Risk: "medium", InputSchema: server.ObjectSchema(nil, nil), Handler: logcatClear})
	reg.Register(server.Tool{Name: "logcat.tail", Description: "Read last N logcat lines.", InputSchema: server.ObjectSchema(map[string]any{"lines": server.IntProp("Line count"), "format": server.StringProp("logcat -v format, default threadtime")}, nil), Handler: logcatTail})
	reg.Register(server.Tool{Name: "logcat.by_pid", Description: "Read logcat and filter lines by PID.", InputSchema: server.ObjectSchema(map[string]any{"pid": server.IntProp("PID"), "lines": server.IntProp("Line count")}, []string{"pid"}), Handler: logcatByPID})
	reg.Register(server.Tool{Name: "logcat.by_package", Description: "Resolve package PID and filter logcat lines.", InputSchema: server.ObjectSchema(map[string]any{"packageName": server.StringProp("Target package"), "lines": server.IntProp("Line count")}, []string{"packageName"}), Handler: logcatByPackage})
	reg.Register(server.Tool{Name: "logcat.grep", Description: "Read logcat and filter by substring or regex.", InputSchema: server.ObjectSchema(map[string]any{"pattern": server.StringProp("Substring or regex"), "regex": server.BoolProp("Treat pattern as regex"), "lines": server.IntProp("Line count")}, []string{"pattern"}), Handler: logcatGrep})
}

func logcatClear(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	r := env.Exec(ctx, 10*time.Second, "logcat", "-c")
	return map[string]any{"result": commandJSON(r)}, nil
}

func logcatTail(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	lines := intArg(args, "lines", env.Config.MaxLogcatLines)
	if lines <= 0 {
		lines = env.Config.MaxLogcatLines
	}
	if lines > 5000 {
		lines = 5000
	}
	format := strArg(args, "format", "threadtime")
	r := env.Exec(ctx, 20*time.Second, "logcat", "-d", "-v", format, "-t", strconvI(lines))
	return map[string]any{"lines": outputLines(r.Stdout), "count": len(outputLines(r.Stdout)), "result": commandJSON(r)}, nil
}

func logcatByPID(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pid := intArg(args, "pid", 0)
	lines := intArg(args, "lines", env.Config.MaxLogcatLines)
	raw, _ := logcatTail(ctx, env, map[string]any{"lines": lines, "format": "threadtime"})
	ls := raw.(map[string]any)["lines"].([]string)
	needle := " " + strconvI(pid) + " "
	out := []string{}
	for _, l := range ls {
		if strings.Contains(l, needle) {
			out = append(out, l)
		}
	}
	return map[string]any{"pid": pid, "lines": out, "count": len(out)}, nil
}

func logcatByPackage(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pkg, err := requirePackage(args)
	if err != nil {
		return nil, err
	}
	pid, _ := pidByPackage(ctx, env, pkg)
	if pid == 0 {
		return map[string]any{"packageName": pkg, "pid": nil, "lines": []string{}, "count": 0}, nil
	}
	res, err := logcatByPID(ctx, env, map[string]any{"pid": pid, "lines": intArg(args, "lines", env.Config.MaxLogcatLines)})
	if err != nil {
		return nil, err
	}
	m := res.(map[string]any)
	m["packageName"] = pkg
	return m, nil
}

func logcatGrep(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	pat := strArg(args, "pattern", "")
	raw, _ := logcatTail(ctx, env, map[string]any{"lines": intArg(args, "lines", env.Config.MaxLogcatLines), "format": "threadtime"})
	ls := raw.(map[string]any)["lines"].([]string)
	out := []string{}
	if boolArg(args, "regex", false) {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		for _, l := range ls {
			if re.MatchString(l) {
				out = append(out, l)
			}
		}
	} else {
		for _, l := range ls {
			if strings.Contains(strings.ToLower(l), strings.ToLower(pat)) {
				out = append(out, l)
			}
		}
	}
	return map[string]any{"pattern": pat, "lines": out, "count": len(out)}, nil
}

func strconvI(i int) string { return strconv.Itoa(i) }
