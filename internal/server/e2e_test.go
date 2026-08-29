package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/store"
)

// TestE2EWebFinger verifies the real server serves WebFinger over HTTP.
func TestE2EWebFinger(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)
	code, body := ts.get(t, "/.well-known/webfinger?resource=acct:alice@example.com", "alice.example.com")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, `"subject":"acct:alice@example.com"`) {
		t.Fatalf("missing subject: %q", body)
	}
}

// TestE2EProfile verifies the content-negotiated profile endpoint.
func TestE2EProfile(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	// Seed a published profile so the h-card renders store data.
	if err := ts.srv.store.UpsertProfilePage(context.Background(), &store.ProfilePage{
		ID:          "p1",
		TenantID:    "t1",
		AccountID:   "acct1",
		DisplayName: "Alice A.",
		IsPublished: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Default (h-card).
	code, body := ts.get(t, "/profile/", "alice.example.com")
	if code != http.StatusOK {
		t.Fatalf("h-card status = %d, want 200", code)
	}
	if !strings.Contains(body, "h-card") {
		t.Fatalf("missing h-card: %q", body)
	}

	// DID doc via Accept: application/did+json.
	req, _ := http.NewRequest(http.MethodGet, ts.baseURL+"/profile/", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Accept", "application/did+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("did doc: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("did doc status = %d, want 200", resp.StatusCode)
	}
}

// TestE2EKeys verifies the keys + proofs endpoints.
func TestE2EKeys(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	code, _ := ts.get(t, "/keys", "alice.example.com")
	if code != http.StatusOK {
		t.Fatalf("/keys status = %d, want 200", code)
	}
	code, _ = ts.get(t, "/.well-known/proofs", "alice.example.com")
	if code != http.StatusOK {
		t.Fatalf("/.well-known/proofs status = %d, want 200", code)
	}
}

// TestE2EAtproto verifies the XRPC resolveHandle endpoint.
func TestE2EAtproto(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)
	code, body := ts.get(t, "/xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com", "alice.example.com")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, "did:web:alice.example.com") {
		t.Fatalf("missing did: %q", body)
	}
}

// TestE2EUnknownTenant verifies an unknown host is a 404 over real HTTP.
func TestE2EUnknownTenant(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)
	code, _ := ts.get(t, "/.well-known/webfinger?resource=acct:x@evil.com", "evil.com")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}

// TestE2EGracefulShutdown verifies the server shuts down cleanly when the
// context is cancelled (the SIGINT/SIGTERM path).
func TestE2EGracefulShutdown(t *testing.T) {
	cfg := &Config{}
	cfg.DataDir = t.TempDir()
	cfg.Domain = "example.com"
	cfg.Storage.Backend = "fs"
	cfg.Log.Level = "info"
	cfg.Log.Format = "text"

	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, ln)
	}()

	// Cancel the context (simulates SIGINT/SIGTERM) and expect clean exit.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down cleanly")
	}
}

// TestRunListenError verifies Run returns an error when the address is
// already in use (the net.Listen error path).
func TestRunListenError(t *testing.T) {
	cfg := &Config{}
	cfg.DataDir = t.TempDir()
	cfg.Domain = "example.com"
	cfg.Storage.Backend = "fs"
	cfg.Log.Level = "info"
	cfg.Log.Format = "text"

	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Occupy a port, then try to Run on it -> listen error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	if err := srv.Run(context.Background(), ln.Addr().String()); err == nil {
		t.Fatal("expected listen error on occupied port")
	}
}

// TestServeServeError verifies Serve returns a non-ErrServerClosed error
// when the listener fails after accept.
func TestServeServeError(t *testing.T) {
	cfg := &Config{}
	cfg.DataDir = t.TempDir()
	cfg.Domain = "example.com"
	cfg.Storage.Backend = "fs"
	cfg.Log.Level = "info"
	cfg.Log.Format = "text"

	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// A closed listener makes Serve return an error immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()

	if err := srv.Serve(context.Background(), ln); err == nil {
		t.Fatal("expected error on closed listener")
	}
}
