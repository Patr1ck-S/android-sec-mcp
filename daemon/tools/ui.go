package tools

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"time"

	"android-sec-mcp/daemon/safety"
	"android-sec-mcp/daemon/server"
)

func registerUI(reg *server.Registry) {
	reg.Register(server.Tool{Name: "ui.dump_xml", Description: "Dump current UI hierarchy XML with uiautomator.", InputSchema: server.ObjectSchema(map[string]any{"path": server.StringProp("Output XML path on device")}, nil), Handler: uiDumpXML})
	reg.Register(server.Tool{Name: "ui.summary", Description: "Dump and summarize visible UI nodes (text/resource-id/class/bounds).", InputSchema: server.ObjectSchema(map[string]any{"path": server.StringProp("Optional XML path"), "limit": server.IntProp("Maximum nodes")}, nil), Handler: uiSummary})
}

func uiDumpXML(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	path := strArg(args, "path", "")
	if path == "" {
		path = filepath.Join(env.Config.WorkspaceDir, "ui", safety.SafeName(time.Now().Format("20060102-150405"))+".xml")
	}
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	r := env.Exec(ctx, 20*time.Second, "uiautomator", "dump", path)
	return map[string]any{"path": path, "result": commandJSON(r)}, nil
}

type UINode struct {
	Text, ResourceID, Class, ContentDesc, Bounds string `json:",omitempty"`
}

func uiSummary(ctx context.Context, env *server.Env, args map[string]any) (any, error) {
	limit := intArg(args, "limit", 80)
	res, err := uiDumpXML(ctx, env, args)
	if err != nil {
		return nil, err
	}
	path := res.(map[string]any)["path"].(string)
	b, err := os.ReadFile(path)
	if err != nil {
		return res, nil
	}
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	nodes := []map[string]string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "node" {
			continue
		}
		n := map[string]string{}
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "text", "resource-id", "class", "content-desc", "bounds", "clickable", "enabled":
				if a.Value != "" {
					n[a.Name.Local] = a.Value
				}
			}
		}
		if len(n) > 0 {
			nodes = append(nodes, n)
		}
		if len(nodes) >= limit {
			break
		}
	}
	return map[string]any{"path": path, "nodes": nodes, "count": len(nodes), "dump": res}, nil
}
