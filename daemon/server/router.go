package server

import (
	"net/http"
)

func NewRouter(env *Env, reg *Registry) http.Handler {
	mux := http.NewServeMux()
	mcp := &MCPHandler{Env: env, Reg: reg}
	mux.Handle("/mcp", BearerAuth(env.Config.Token, mcp))
	mux.Handle("/health", BearerAuth(env.Config.Token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "name": "android-sec-mcp", "version": env.Version, "bindAddr": env.Config.BindAddr})
	})))
	mux.Handle("/", BearerAuth(env.Config.Token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"name": "android-sec-mcp", "mcp": "/mcp", "health": "/health"})
	})))
	return mux
}
