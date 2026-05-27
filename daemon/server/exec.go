package server

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type CommandResult struct {
	Command  string   `json:"command"`
	Args     []string `json:"args"`
	ExitCode int      `json:"exitCode"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
	TimedOut bool     `json:"timedOut"`
	Duration string   `json:"duration"`
}

type Env struct {
	Config   *Config
	Audit    *AuditLogger
	Sessions *SessionStore
	Version  string
}

func NewEnv(cfg *Config, version string) *Env {
	return &Env{Config: cfg, Audit: NewAuditLogger(cfg.AuditLogPath), Sessions: NewSessionStore(), Version: version}
}

func (e *Env) Exec(ctx context.Context, timeout time.Duration, name string, args ...string) CommandResult {
	if timeout <= 0 {
		timeout = e.Config.CommandTimeout()
	}
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var out, er bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &er
	err := cmd.Run()
	exit := 0
	if err != nil {
		exit = -1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
	}
	return CommandResult{
		Command:  name,
		Args:     args,
		ExitCode: exit,
		Stdout:   out.String(),
		Stderr:   er.String(),
		TimedOut: cctx.Err() == context.DeadlineExceeded,
		Duration: time.Since(start).String(),
	}
}

func (e *Env) ExecOK(ctx context.Context, name string, args ...string) (string, error) {
	r := e.Exec(ctx, e.Config.CommandTimeout(), name, args...)
	if r.ExitCode != 0 {
		return r.Stdout, fmt.Errorf("%s %s failed: exit=%d stderr=%s", name, strings.Join(args, " "), r.ExitCode, strings.TrimSpace(r.Stderr))
	}
	return r.Stdout, nil
}
