// Package server wires the identity server's protocol handlers, storage,
// and middleware into a runnable HTTP server. It is the integration layer
// that turns the packages into a deployable single binary.
package server

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the server configuration, loaded from config.yml.
type Config struct {
	Domain       string        `yaml:"domain"`
	IdentityHost string        `yaml:"identity_host"`
	DataDir      string        `yaml:"data_dir"`
	Storage      StorageConfig `yaml:"storage"`
	SQLite       SQLiteConfig  `yaml:"sqlite"`
	TLS          TLSConfig     `yaml:"tls"`
	IPFS         IPFSConfig    `yaml:"ipfs"`
	Atproto      AtprotoConfig `yaml:"atproto"`
	Backup       BackupConfig  `yaml:"backup"`
	Log          LogConfig     `yaml:"log"`
}

// StorageConfig configures the protocol blob backend.
type StorageConfig struct {
	Backend string    `yaml:"backend"` // "fs" | "s3"
	S3      *S3Config `yaml:"s3"`
}

// S3Config configures an S3-compatible blob backend.
type S3Config struct {
	Endpoint  string `yaml:"endpoint"`
	Bucket    string `yaml:"bucket"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Region    string `yaml:"region"`
}

// SQLiteConfig configures the account-data store.
type SQLiteConfig struct {
	Mode   string `yaml:"mode"` // "per_tenant" | "single"
	Single *struct {
		Path string `yaml:"path"`
	} `yaml:"single"`
}

// TLSConfig configures ACME/certmagic.
type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Email   string `yaml:"email"`
}

// IPFSConfig configures the IPFS pinning broker.
type IPFSConfig struct {
	Enabled bool `yaml:"enabled"`
}

// AtprotoConfig configures the PDS.
type AtprotoConfig struct {
	DIDMethod string `yaml:"did_method"`
}

// BackupConfig configures scheduled backups.
type BackupConfig struct {
	CronExpr string `yaml:"cron_expr"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	// #nosec G304 -- path is a caller-provided config path (CLI flag), not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks required config fields.
func (c *Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("config: domain is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("config: data_dir is required")
	}
	if c.Storage.Backend == "" {
		c.Storage.Backend = "fs"
	}
	if c.Storage.Backend != "fs" && c.Storage.Backend != "s3" {
		return fmt.Errorf("config: storage.backend must be fs or s3, got %q", c.Storage.Backend)
	}
	if c.SQLite.Mode == "" {
		c.SQLite.Mode = "per_tenant"
	}
	if c.SQLite.Mode != "per_tenant" && c.SQLite.Mode != "single" {
		return fmt.Errorf("config: sqlite.mode must be per_tenant or single, got %q", c.SQLite.Mode)
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	return nil
}
