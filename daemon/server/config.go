package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultConfigPath = "/data/adb/android-sec-mcp/config.json"
	DefaultDataDir    = "/data/adb/android-sec-mcp"
	DefaultWorkspace  = "/data/local/tmp/android-sec-mcp/cases"
	DefaultBindAddr   = "127.0.0.1:8765"
)

type Config struct {
	BindAddr              string `json:"bindAddr"`
	Token                 string `json:"token"`
	WorkspaceDir          string `json:"workspaceDir"`
	DataDir               string `json:"dataDir"`
	AuditLogPath          string `json:"auditLogPath"`
	FridaServerPath       string `json:"fridaServerPath"`
	FridaCliPath          string `json:"fridaCliPath"`
	FridaHost             string `json:"fridaHost"`
	CommandTimeoutSeconds int    `json:"commandTimeoutSeconds"`
	MaxLogcatLines        int    `json:"maxLogcatLines"`

	CTFBypassEnabled      bool     `json:"ctfBypassEnabled"`
	AllowedBypassPackages []string `json:"allowedBypassPackages"`
	BypassProfilesDir     string   `json:"bypassProfilesDir"`
}

func DefaultConfig() *Config {
	return &Config{
		BindAddr:              DefaultBindAddr,
		Token:                 mustToken(),
		WorkspaceDir:          DefaultWorkspace,
		DataDir:               DefaultDataDir,
		AuditLogPath:          filepath.Join(DefaultDataDir, "audit.log"),
		FridaServerPath:       "/data/local/tmp/frida-server",
		FridaCliPath:          "",
		FridaHost:             "127.0.0.1:27042",
		CommandTimeoutSeconds: 30,
		MaxLogcatLines:        500,
		CTFBypassEnabled:      false,
		AllowedBypassPackages: []string{},
		BypassProfilesDir:     filepath.Join(DefaultDataDir, "bypass-profiles"),
	}
}

func LoadOrCreateConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	if b, err := os.ReadFile(path); err == nil {
		cfg := DefaultConfig()
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		cfg.applyDefaults()
		if cfg.Token == "" {
			cfg.Token = mustToken()
			if err := SaveConfig(path, cfg); err != nil {
				return nil, err
			}
		}
		return cfg, cfg.EnsureDirs()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := cfg.EnsureDirs(); err != nil {
		return nil, err
	}
	if err := SaveConfig(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	if path == "" {
		path = DefaultConfigPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

func (c *Config) applyDefaults() {
	d := DefaultConfig()
	if c.BindAddr == "" {
		c.BindAddr = d.BindAddr
	}
	if c.WorkspaceDir == "" {
		c.WorkspaceDir = d.WorkspaceDir
	}
	if c.DataDir == "" {
		c.DataDir = d.DataDir
	}
	if c.AuditLogPath == "" {
		c.AuditLogPath = filepath.Join(c.DataDir, "audit.log")
	}
	if c.FridaServerPath == "" {
		c.FridaServerPath = d.FridaServerPath
	}
	if c.FridaHost == "" {
		c.FridaHost = d.FridaHost
	}
	if c.CommandTimeoutSeconds <= 0 {
		c.CommandTimeoutSeconds = d.CommandTimeoutSeconds
	}
	if c.MaxLogcatLines <= 0 {
		c.MaxLogcatLines = d.MaxLogcatLines
	}
	if c.BypassProfilesDir == "" {
		c.BypassProfilesDir = filepath.Join(c.DataDir, "bypass-profiles")
	}
}

func (c *Config) EnsureDirs() error {
	c.applyDefaults()
	dirs := []string{c.DataDir, c.WorkspaceDir, c.BypassProfilesDir, filepath.Dir(c.AuditLogPath)}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

func (c *Config) CommandTimeout() time.Duration {
	if c.CommandTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.CommandTimeoutSeconds) * time.Second
}

func mustToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("dev-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
