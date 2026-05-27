package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"android-sec-mcp/daemon/server"
	"android-sec-mcp/daemon/tools"
)

const version = "0.1.0-root-edition"

func main() {
	cfgPath := flag.String("config", server.DefaultConfigPath, "config path")
	printToken := flag.Bool("print-token", false, "print bearer token and exit")
	flag.Parse()

	cfg, err := server.LoadOrCreateConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *printToken {
		fmt.Println(cfg.Token)
		return
	}
	if err := cfg.EnsureDirs(); err != nil {
		log.Fatalf("dirs: %v", err)
	}
	if !strings.HasPrefix(cfg.BindAddr, "127.0.0.1:") && !strings.HasPrefix(cfg.BindAddr, "localhost:") {
		log.Fatalf("refusing to listen on non-loopback address %q; set 127.0.0.1:PORT", cfg.BindAddr)
	}

	env := server.NewEnv(cfg, version)
	reg := server.NewRegistry()
	tools.RegisterAll(reg)
	handler := server.NewRouter(env, reg)

	ln, err := net.Listen("tcp", cfg.BindAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.BindAddr, err)
	}
	log.Printf("android-sec-mcp %s listening on http://%s/mcp pid=%d", version, cfg.BindAddr, os.Getpid())
	log.Printf("workspace=%s config=%s audit=%s", cfg.WorkspaceDir, *cfgPath, cfg.AuditLogPath)
	if err := http.Serve(ln, handler); err != nil {
		log.Fatal(err)
	}
}
