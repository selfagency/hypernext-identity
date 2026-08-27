package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes a test config file.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadConfig verifies config parsing + defaults.
func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `domain: example.com
data_dir: ./data
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Domain != "example.com" {
		t.Fatalf("domain = %q", cfg.Domain)
	}
	// Defaults applied.
	if cfg.Storage.Backend != "fs" {
		t.Fatalf("storage.backend = %q, want fs", cfg.Storage.Backend)
	}
	if cfg.SQLite.Mode != "per_tenant" {
		t.Fatalf("sqlite.mode = %q, want per_tenant", cfg.SQLite.Mode)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("log.level = %q, want info", cfg.Log.Level)
	}
}

// TestLoadConfigMissingFile verifies a missing config errors.
func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig("/nonexistent/config.yml"); err == nil {
		t.Fatal("expected error for missing config")
	}
}

// TestLoadConfigInvalid verifies an invalid config errors.
func TestLoadConfigInvalid(t *testing.T) {
	path := writeConfig(t, `domain: ""`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

// TestLoadConfigInvalidBackend verifies an invalid backend errors.
func TestLoadConfigInvalidBackend(t *testing.T) {
	path := writeConfig(t, `domain: example.com
data_dir: ./data
storage:
  backend: gcs
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for invalid backend")
	}
}

// TestNewServer verifies server assembly.
func TestNewServer(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		SQLite:  SQLiteConfig{Mode: "single"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	if srv == nil {
		t.Fatal("nil server")
	}
}

// TestServerRoutes verifies the assembled router serves known endpoints.
func TestServerRoutes(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		SQLite:  SQLiteConfig{Mode: "single"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	cases := []struct {
		path string
		host string
		want int
	}{
		{"/.well-known/webfinger?resource=acct:alice@example.com", "alice.example.com", http.StatusOK},
		{"/.well-known/nodeinfo", "alice.example.com", http.StatusOK},
		{"/.well-known/proofs", "alice.example.com", http.StatusOK},
		{"/keys", "alice.example.com", http.StatusOK},
		{"/profile/", "alice.example.com", http.StatusOK},
		{"/rs/docs/x", "alice.example.com", http.StatusUnauthorized}, // no token
		{"/unknown", "alice.example.com", http.StatusNotFound},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, http.NoBody)
		req.Host = c.host
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Fatalf("GET %s (host %s) = %d, want %d", c.path, c.host, rec.Code, c.want)
		}
	}
}

// TestServerUnknownTenant verifies an unknown host is a 404.
func TestServerUnknownTenant(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		SQLite:  SQLiteConfig{Mode: "single"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:x@evil.com", http.NoBody)
	req.Host = "evil.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host = %d, want 404", rec.Code)
	}
}

// TestStaticTenantStore verifies subdomain resolution.
func TestStaticTenantStore(t *testing.T) {
	ts := staticTenantStore{domain: "example.com"}
	ctx := context.Background()

	// Root domain.
	t1, err := ts.FindByHost(ctx, "example.com")
	if err != nil || t1.Handle != "example.com" {
		t.Fatalf("root = %+v, %v", t1, err)
	}
	// Subdomain.
	t2, err := ts.FindByHost(ctx, "alice.example.com")
	if err != nil || t2.Handle != "alice.example.com" {
		t.Fatalf("subdomain = %+v, %v", t2, err)
	}
	// Unknown.
	if _, err := ts.FindByHost(ctx, "evil.com"); err == nil {
		t.Fatal("expected error for unknown host")
	}
}
