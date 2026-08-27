package atproto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hypernext/identity/internal/store"
)

// TestSpecConformanceResolveHandle verifies com.atproto.identity.resolveHandle
// returns the exact XRPC shape: {"did": "<did>"} with application/json.
// https://atproto.com/lexicons/com-atproto-identity#comatprotoidentityresolvehandle
func TestSpecConformanceResolveHandle(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	_ = s.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	x := &XRPCServer{Store: s}
	req := httptest.NewRequest("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	// The response must be exactly {"did": "did:web:alice.example.com"}.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("response has %d keys, want exactly 1 (did): %v", len(raw), raw)
	}
	if raw["did"] != "did:web:alice.example.com" {
		t.Fatalf("did = %v, want did:web:alice.example.com", raw["did"])
	}
}

// TestSpecConformanceResolveHandleError verifies the XRPC error shape:
// {"error": "<code>", "message": "<msg>"} with the correct status.
func TestSpecConformanceResolveHandleError(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	x := &XRPCServer{Store: s}

	// Missing handle -> 400 InvalidRequest.
	req := httptest.NewRequest("GET", "/xrpc/com.atproto.identity.resolveHandle", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing handle status = %d, want 400", rec.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["error"] != "InvalidRequest" {
		t.Fatalf("error = %v, want InvalidRequest", raw["error"])
	}

	// Unknown handle -> 404 HandleNotFound.
	req2 := httptest.NewRequest("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=unknown.example.com", http.NoBody)
	rec2 := httptest.NewRecorder()
	x.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("unknown handle status = %d, want 404", rec2.Code)
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["error"] != "HandleNotFound" {
		t.Fatalf("error = %v, want HandleNotFound", raw["error"])
	}
}
