package atproto

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockXRPCServer serves resolveHandle and getProfile.
func mockXRPCServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/xrpc/com.atproto.identity.resolveHandle", func(w http.ResponseWriter, r *http.Request) {
		handle := r.URL.Query().Get("handle")
		if handle == "" {
			http.Error(w, `{"error":"InvalidRequest","message":"missing handle"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"did":"did:plc:abc123"}`))
	})
	mux.HandleFunc("/xrpc/app.bsky.actor.getProfile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"did":"did:plc:abc123","handle":"alice.example.com","displayName":"Alice"}`))
	})
	return httptest.NewServer(mux)
}

// TestXRPCResolveHandle verifies handle resolution via XRPC.
func TestXRPCResolveHandle(t *testing.T) {
	srv := mockXRPCServer(t)
	defer srv.Close()
	c := NewXRPCClient(srv.URL)

	did, err := c.ResolveHandle(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	if did != "did:plc:abc123" {
		t.Fatalf("did = %q, want did:plc:abc123", did)
	}
}

// TestXRPCGetProfile verifies profile retrieval.
func TestXRPCGetProfile(t *testing.T) {
	srv := mockXRPCServer(t)
	defer srv.Close()
	c := NewXRPCClient(srv.URL)

	profile, err := c.GetProfile(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if profile["displayName"] != "Alice" {
		t.Fatalf("displayName = %v", profile["displayName"])
	}
}

// TestXRPCError verifies a non-200 response returns an error.
func TestXRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"InvalidRequest","message":"bad"}`))
	}))
	defer srv.Close()
	c := NewXRPCClient(srv.URL)

	if _, err := c.ResolveHandle(context.Background(), "x"); err == nil {
		t.Fatal("expected error on 400")
	}
}
