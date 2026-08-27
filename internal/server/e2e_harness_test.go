package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hypernext/identity/internal/store"
)

// fillDefaults applies test defaults to a config so callers can pass a
// minimal &Config{}.
func fillDefaults(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	if cfg.Domain == "" {
		cfg.Domain = "example.com"
	}
	if cfg.Storage.Backend == "" {
		cfg.Storage.Backend = "fs"
	}
	if cfg.SQLite.Mode == "" {
		cfg.SQLite.Mode = "single"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "text"
	}
}

// testServer is a running server instance bound to a real TCP socket.
type testServer struct {
	baseURL string
	srv     *Server
	done    chan error
}

// startTestServer boots a real server on a random localhost port and returns
// a handle. It seeds a tenant so the tenant middleware resolves the host.
func startTestServer(t *testing.T, cfg *Config, seedTenant bool) *testServer {
	t.Helper()
	fillDefaults(t, cfg)

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	if seedTenant {
		_ = srv.store.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})
	}

	// Bind a real listener on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(context.Background(), ln)
	}()

	// Wait for the listener to accept.
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	return &testServer{baseURL: baseURL, srv: srv, done: done}
}

// get performs a GET with the given Host header and returns status + body.
func (ts *testServer) get(t *testing.T, path, host string) (status int, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.baseURL+path, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
