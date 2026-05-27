package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditLogger struct {
	path string
	mu   sync.Mutex
}

func NewAuditLogger(path string) *AuditLogger { return &AuditLogger{path: path} }

func (a *AuditLogger) Log(event string, fields map[string]any) {
	if a == nil || a.path == "" {
		return
	}
	rec := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"event": event,
	}
	for k, v := range fields {
		rec[k] = v
	}
	b, _ := json.Marshal(rec)
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = os.MkdirAll(filepath.Dir(a.path), 0700)
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}
