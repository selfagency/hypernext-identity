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
// Both yaml and mapstructure tags are present: yaml for the file loader,
// mapstructure for Viper's Unmarshal (the CLI path).
type Config struct {
	Domain       string        `yaml:"domain" mapstructure:"domain"`
	IdentityHost string        `yaml:"identity_host" mapstructure:"identity_host"`
	DataDir      string        `yaml:"data_dir" mapstructure:"data_dir"`
	Storage      StorageConfig `yaml:"storage" mapstructure:"storage"`
	SQLite       SQLiteConfig  `yaml:"sqlite" mapstructure:"sqlite"`
	TLS          TLSConfig     `yaml:"tls" mapstructure:"tls"`
	IPFS         IPFSConfig    `yaml:"ipfs" mapstructure:"ipfs"`
	Atproto      AtprotoConfig `yaml:"atproto" mapstructure:"atproto"`
	Backup       BackupConfig  `yaml:"backup" mapstructure:"backup"`
	SMTP         SMTPConfig    `yaml:"smtp" mapstructure:"smtp"`
	Log          LogConfig     `yaml:"log" mapstructure:"log"`
}

// StorageConfig configures the protocol blob backend.
type StorageConfig struct {
	Backend string    `yaml:"backend" mapstructure:"backend"` // "fs" | "s3"
	S3      *S3Config `yaml:"s3" mapstructure:"s3"`
}

// S3Config configures an S3-compatible blob backend.
type S3Config struct {
	Endpoint  string `yaml:"endpoint" mapstructure:"endpoint"`
	Bucket    string `yaml:"bucket" mapstructure:"bucket"`
	AccessKey string `yaml:"access_key" mapstructure:"access_key"`
	SecretKey string `yaml:"secret_key" mapstructure:"secret_key"`
	Region    string `yaml:"region" mapstructure:"region"`
}

// SQLiteConfig configures the account-data store.
type SQLiteConfig struct {
	Mode   string `yaml:"mode" mapstructure:"mode"` // "per_tenant" | "single"
	Single *struct {
		Path string `yaml:"path" mapstructure:"path"`
	} `yaml:"single" mapstructure:"single"`
}

// TLSConfig configures ACME/certmagic.
type TLSConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Email   string `yaml:"email" mapstructure:"email"`
}

// IPFSConfig configures the IPFS pinning broker.
type IPFSConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
}

// AtprotoConfig configures the PDS.
type AtprotoConfig struct {
	DIDMethod string `yaml:"did_method" mapstructure:"did_method"`
}

// BackupConfig configures scheduled backups.
type BackupConfig struct {
	CronExpr string `yaml:"cron_expr" mapstructure:"cron_expr"`
}

// SMTPConfig configures outbound email via stdlib net/smtp.
type SMTPConfig struct {
	Host     string `yaml:"host" mapstructure:"host"`
	Port     int    `yaml:"port" mapstructure:"port"`
	Username string `yaml:"username" mapstructure:"username"`
	Password string `yaml:"password" mapstructure:"password"`
	From     string `yaml:"from" mapstructure:"from"`
	TLS      bool   `yaml:"tls" mapstructure:"tls"` // STARTTLS
}

// Enabled reports whether SMTP is configured for sending.
func (s *SMTPConfig) Enabled() bool {
	return s.Host != "" && s.Port != 0
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
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
