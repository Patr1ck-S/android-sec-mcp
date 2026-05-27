package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type FridaSession struct {
	ID          string    `json:"id"`
	PackageName string    `json:"packageName,omitempty"`
	PID         int       `json:"pid"`
	ScriptPath  string    `json:"scriptPath,omitempty"`
	StartedAt   time.Time `json:"startedAt"`
	Loaded      bool      `json:"loaded"`
	Note        string    `json:"note,omitempty"`
	PCMode      *PCMode   `json:"pcMode,omitempty"`

	Messages []string `json:"messages,omitempty"`
	cancel   context.CancelFunc
	cmd      *exec.Cmd
}

type PCMode struct {
	Enabled            bool     `json:"enabled"`
	Reason             string   `json:"reason"`
	ScriptPathOnDevice string   `json:"scriptPathOnDevice"`
	SaveAs             string   `json:"saveAs"`
	Script             string   `json:"script,omitempty"`
	Commands           []string `json:"commands"`
	Notes              []string `json:"notes"`
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*FridaSession
}

func NewSessionStore() *SessionStore { return &SessionStore{sessions: map[string]*FridaSession{}} }

func (s *SessionStore) New(packageName string, pid int) *FridaSession {
	sess := &FridaSession{ID: fmt.Sprintf("frida-%d", time.Now().UnixNano()), PackageName: packageName, PID: pid, StartedAt: time.Now()}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

func (s *SessionStore) Put(sess *FridaSession) {
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
}

func (s *SessionStore) Get(id string) (*FridaSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *SessionStore) Append(id string, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.Messages = append(sess.Messages, line)
		if len(sess.Messages) > 2000 {
			sess.Messages = sess.Messages[len(sess.Messages)-2000:]
		}
	}
}

func (s *SessionStore) Stop(id string) bool {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if ok && sess.cancel != nil {
		sess.cancel()
	}
	if ok && sess.cmd != nil && sess.cmd.Process != nil {
		_ = sess.cmd.Process.Kill()
	}
	return ok
}

func (e *Env) StartFridaScript(ctx context.Context, sess *FridaSession, scriptPath string) (*FridaSession, error) {
	sess.ScriptPath = scriptPath
	if e.Config.FridaCliPath == "" {
		sess.Loaded = false
		sess.Note = "fridaCliPath is not configured on device; script generated but not loaded. Configure a frida CLI/frida-inject compatible binary to enable runtime loading."
		sess.PCMode = BuildPCMode(sess, scriptPath, sess.Note)
		e.Sessions.Put(sess)
		return sess, nil
	}
	cctx, cancel := context.WithCancel(ctx)
	args := []string{"-H", e.Config.FridaHost, "-p", fmt.Sprintf("%d", sess.PID), "-l", scriptPath}
	cmd := exec.CommandContext(cctx, e.Config.FridaCliPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		sess.Loaded = false
		sess.Note = err.Error()
		e.Sessions.Put(sess)
		return sess, nil
	}
	sess.cancel = cancel
	sess.cmd = cmd
	sess.Loaded = true
	sess.Note = "started " + filepath.Base(e.Config.FridaCliPath)
	e.Sessions.Put(sess)
	pump := func(r io.Reader, prefix string) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 4096), 1024*1024)
		for sc.Scan() {
			e.Sessions.Append(sess.ID, prefix+sc.Text())
		}
	}
	go pump(stdout, "")
	go pump(stderr, "[stderr] ")
	go func() {
		err := cmd.Wait()
		if err != nil {
			e.Sessions.Append(sess.ID, "[exit] "+err.Error())
		} else {
			e.Sessions.Append(sess.ID, "[exit] ok")
		}
	}()
	return sess, nil
}

func BuildPCMode(sess *FridaSession, scriptPath string, reason string) *PCMode {
	saveAs := filepath.Base(scriptPath)
	if saveAs == "." || saveAs == string(filepath.Separator) || saveAs == "" {
		saveAs = "android-sec-mcp-frida.js"
	}
	script := ""
	if b, err := os.ReadFile(scriptPath); err == nil {
		script = string(b)
	}
	target := ""
	if sess.PID > 0 {
		target = fmt.Sprintf("-p %d", sess.PID)
	} else if sess.PackageName != "" {
		target = fmt.Sprintf("-n %s", sess.PackageName)
	}
	commands := []string{
		"# 1) Export the generated JS from Android to the PC",
		fmt.Sprintf("adb exec-out su -c \"cat %s\" > %s", shellQuote(scriptPath), shellQuote(saveAs)),
		"# If the script path is adb-readable on your device, this may also work:",
		fmt.Sprintf("adb pull %s %s", shellQuote(scriptPath), shellQuote(saveAs)),
		"# 2) Make sure frida-server is running on the Android device",
	}
	if target != "" {
		commands = append(commands,
			"# Option A: use USB device from PC",
			fmt.Sprintf("frida -U %s -l %s", target, saveAs),
			"# Option B: use adb forward from PC",
			"adb forward tcp:27042 tcp:27042",
			fmt.Sprintf("frida -H 127.0.0.1:27042 %s -l %s", target, saveAs),
		)
	}
	if sess.PackageName != "" {
		commands = append(commands,
			"# Option C: spawn early injection from PC, recommended for early root/debug/frida checks",
			fmt.Sprintf("frida -U -f %s -l %s", sess.PackageName, saveAs),
			"# Option D: spawn early injection through adb forward",
			"adb forward tcp:27042 tcp:27042",
			fmt.Sprintf("frida -H 127.0.0.1:27042 -f %s -l %s", sess.PackageName, saveAs),
		)
	}
	return &PCMode{
		Enabled:            true,
		Reason:             reason,
		ScriptPathOnDevice: scriptPath,
		SaveAs:             saveAs,
		Script:             script,
		Commands:           commands,
		Notes: []string{
			"PC-side mode is intended for the common setup where frida-server runs on Android and frida-tools runs on the PC.",
			"The script is generated on Android; export it to the PC with the adb command above before running frida.",
			"Spawn early injection uses `frida -f <package> -l <script>` so the script is loaded before the app starts executing most Java code.",
			"If the target app restarts, refresh the PID and rerun the frida command.",
		},
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
