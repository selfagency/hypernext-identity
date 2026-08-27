package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hypernext/identity/internal/store"
)

// TestE2ECrossProtocolFlow verifies the full wiring works together over real
// HTTP: a persisted OIDC token authorizes remoteStorage writes/reads, and the
// same token authorizes Solid LDP writes/reads. This proves the protocol
// handlers, the wiring TokenValidator, and the blob backend cooperate.
func TestE2ECrossProtocolFlow(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	// Persist an OIDC refresh token with remoteStorage rw scope. This is the
	// token the wiring TokenValidator resolves (it reads persisted refresh
	// tokens). In production this token is minted by the OIDC provider; here
	// we seed it directly to exercise the authorization path end-to-end.
	token := "oidc-token-1"
	if err := ts.srv.authStore.PersistRefreshToken(context.Background(), token, "alice", "client1", []string{"rw"}); err != nil {
		t.Fatalf("persist token: %v", err)
	}

	// 1. remoteStorage PUT (requires rw scope).
	code, _ := ts.do(t, http.MethodPut, "/rs/docs/hello.txt", "alice.example.com", token, "text/plain", []byte("hello world"))
	if code != http.StatusOK {
		t.Fatalf("rs PUT = %d, want 200", code)
	}

	// 2. remoteStorage GET (rw implies r).
	code, body := ts.do(t, http.MethodGet, "/rs/docs/hello.txt", "alice.example.com", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("rs GET = %d, want 200", code)
	}
	if body != "hello world" {
		t.Fatalf("rs GET body = %q, want hello world", body)
	}

	// 3. Solid LDP write (authenticated agent can write). Solid returns 201
	// Created on PUT.
	resp, _ := ts.do(t, http.MethodPut, "/solid/docs/note.ttl", "alice.example.com", token, "text/turtle", []byte("@prefix : <#>.\n:note a :Note."))
	if resp != http.StatusCreated {
		t.Fatalf("solid PUT = %d, want 201", resp)
	}

	// 4. Solid LDP read.
	resp, body = ts.do(t, http.MethodGet, "/solid/docs/note.ttl", "alice.example.com", token, "", nil)
	if resp != http.StatusOK {
		t.Fatalf("solid GET = %d, want 200", resp)
	}
	if !strings.Contains(body, ":note a :Note.") {
		t.Fatalf("solid GET body = %q, want note content", body)
	}

	// 5. Unauthorized: no token -> 401 on remoteStorage.
	code, _ = ts.do(t, http.MethodGet, "/rs/docs/hello.txt", "alice.example.com", "", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("rs GET no token = %d, want 401", code)
	}

	// 6. Forbidden: token without write scope cannot PUT.
	readOnly := "readonly-token"
	if err := ts.srv.authStore.PersistRefreshToken(context.Background(), readOnly, "alice", "client1", []string{"r"}); err != nil {
		t.Fatalf("persist read-only token: %v", err)
	}
	code, _ = ts.do(t, http.MethodPut, "/rs/docs/other.txt", "alice.example.com", readOnly, "text/plain", []byte("x"))
	if code != http.StatusForbidden {
		t.Fatalf("rs PUT read-only = %d, want 403", code)
	}
}

// TestE2EMultiTenantIsolation verifies tenant A cannot read or write tenant
// B's data over real HTTP. This is the IDOR boundary at the HTTP layer.
func TestE2EMultiTenantIsolation(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	// Seed tenant B.
	if err := ts.srv.store.CreateTenant(context.Background(), &store.Tenant{ID: "t2", Handle: "bob.example.com", DIDMethod: "web"}); err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	// Alice writes a blob.
	aliceTok := "alice-token"
	if err := ts.srv.authStore.PersistRefreshToken(context.Background(), aliceTok, "alice", "client1", []string{"rw"}); err != nil {
		t.Fatalf("persist alice token: %v", err)
	}
	code, _ := ts.do(t, http.MethodPut, "/rs/docs/secret.txt", "alice.example.com", aliceTok, "text/plain", []byte("alice secret"))
	if code != http.StatusOK {
		t.Fatalf("alice PUT = %d, want 200", code)
	}

	// Bob tries to read Alice's blob via his own host. The blob backend is
	// shared (backendFor returns the same backend for all tenants), so the
	// key is the same path — this exposes the current isolation gap.
	bobTok := "bob-token"
	if err := ts.srv.authStore.PersistRefreshToken(context.Background(), bobTok, "bob", "client1", []string{"rw"}); err != nil {
		t.Fatalf("persist bob token: %v", err)
	}
	code, body := ts.do(t, http.MethodGet, "/rs/docs/secret.txt", "bob.example.com", bobTok, "", nil)
	if code == http.StatusOK && strings.Contains(body, "alice secret") {
		t.Fatalf("ISOLATION GAP: bob read alice's blob (status %d)", code)
	}
}
