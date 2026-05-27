package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

type MCPHandler struct {
	Env *Env
	Reg *Registry
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"name": "android-sec-mcp", "version": h.Env.Version, "transport": "mcp-streamable-http", "endpoint": "/mcp"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: err.Error()}})
		return
	}
	if req.JSONRPC == "" {
		req.JSONRPC = "2.0"
	}
	if req.ID == nil && strings.HasPrefix(req.Method, "notifications/") {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	res, err := h.handle(r.Context(), req)
	if err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32000, Message: err.Error()}})
		return
	}
	writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res})
}

func (h *MCPHandler) handle(ctx context.Context, req rpcRequest) (any, error) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "android-sec-mcp", "version": h.Env.Version},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := []map[string]any{}
		for _, t := range h.Reg.List() {
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, err
			}
		}
		if p.Arguments == nil {
			p.Arguments = map[string]any{}
		}
		t, ok := h.Reg.Get(p.Name)
		if !ok {
			return nil, fmt.Errorf("unknown tool %q", p.Name)
		}
		start := time.Now()
		h.Env.Audit.Log("tool.call.start", map[string]any{"tool": p.Name, "args": redactArgs(p.Arguments), "risk": t.Risk})
		var result any
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("panic in tool %s: %v\n%s", p.Name, r, string(debug.Stack()))
				}
			}()
			result, err = t.Handler(ctx, h.Env, p.Arguments)
		}()
		status := "ok"
		if err != nil {
			status = "error"
		}
		h.Env.Audit.Log("tool.call.finish", map[string]any{"tool": p.Name, "status": status, "error": errString(err), "durationMs": time.Since(start).Milliseconds()})
		if err != nil {
			return nil, err
		}
		textBytes, _ := json.MarshalIndent(result, "", "  ")
		return map[string]any{
			"content":           []map[string]any{{"type": "text", "text": string(textBytes)}},
			"structuredContent": result,
			"isError":           false,
		}, nil
	default:
		if strings.HasPrefix(req.Method, "notifications/") {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("unsupported method %s", req.Method)
	}
}

func redactArgs(args map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range args {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "password") {
			out[k] = "<redacted>"
		} else {
			out[k] = v
		}
	}
	return out
}
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeRPC(w http.ResponseWriter, v any) { writeJSON(w, v) }
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
