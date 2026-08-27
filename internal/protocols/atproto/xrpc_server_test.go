package atproto

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hypernext/identity/internal/store"
)

// newTestStore opens a temp SQLite store.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestResolveHandle verifies handle -> DID resolution.
func TestResolveHandle(t *testing.T) {
	s := newTestStore(t)
	_ = s.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	x := &XRPCServer{Store: s}
	req := httptest.NewRequest("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "did:web:alice.example.com") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestResolveHandleMissing verifies a missing handle errors.
func TestResolveHandleMissing(t *testing.T) {
	s := newTestStore(t)
	x := &XRPCServer{Store: s}
	req := httptest.NewRequest("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=unknown.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestResolveHandleNoParam verifies a missing handle param errors.
func TestResolveHandleNoParam(t *testing.T) {
	s := newTestStore(t)
	x := &XRPCServer{Store: s}
	req := httptest.NewRequest("GET", "/xrpc/com.atproto.identity.resolveHandle", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestGetProfile verifies profile retrieval.
func TestGetProfile(t *testing.T) {
	s := newTestStore(t)
	_ = s.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	x := &XRPCServer{Store: s}
	req := httptest.NewRequest("GET", "/xrpc/app.bsky.actor.getProfile?actor=alice.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "alice.example.com") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestGetProfileNotFound verifies a missing actor errors.
func TestGetProfileNotFound(t *testing.T) {
	s := newTestStore(t)
	x := &XRPCServer{Store: s}
	req := httptest.NewRequest("GET", "/xrpc/app.bsky.actor.getProfile?actor=unknown.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestUnsupportedMethod verifies an unknown XRPC method errors.
func TestUnsupportedMethod(t *testing.T) {
	s := newTestStore(t)
	x := &XRPCServer{Store: s}
	req := httptest.NewRequest("GET", "/xrpc/com.atproto.unknown", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}
