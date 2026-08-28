package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// mintAccessToken signs a short-lived access token for the given subject and
// scopes using the server's auth signing key.
func mintAccessToken(t *testing.T, ts *testServer, subject string, scopes []string) string {
	t.Helper()
	tok, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), subject, scopes, auth.AccessTokenTTL)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	return tok
}

// TestE2ECrossProtocolFlow verifies the full wiring works together over real
// HTTP: a signed access token authorizes remoteStorage writes/reads, and the
// same token authorizes Solid LDP writes/reads. This proves the protocol
// handlers, the wiring TokenValidator, and the blob backend cooperate.
func TestE2ECrossProtocolFlow(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	// Seed an account owned by alice in tenant t1 so Solid's ownership check
	// (WebID -> account -> tenant) passes.
	if err := ts.srv.store.CreateAccount(context.Background(), &store.Account{
		ID: "a1", TenantID: "t1", DID: "did:web:alice.example.com",
		WebID: "https://alice.example.com/profile/card#me",
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}

	// Mint a signed access token with remoteStorage rw scope. The subject is
	// the account's WebID so Solid's ownership check (WebID -> account ->
	// tenant) resolves. In production this token is minted by the OIDC
	// provider; here we mint it directly to exercise the authorization path
	// end-to-end.
	token := mintAccessToken(t, ts, "https://alice.example.com/profile/card#me", []string{"rw"})

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
	readOnly := mintAccessToken(t, ts, "alice", []string{"r"})
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
	aliceTok := mintAccessToken(t, ts, "alice", []string{"rw"})
	code, _ := ts.do(t, http.MethodPut, "/rs/docs/secret.txt", "alice.example.com", aliceTok, "text/plain", []byte("alice secret"))
	if code != http.StatusOK {
		t.Fatalf("alice PUT = %d, want 200", code)
	}

	// Bob tries to read Alice's blob via his own host. The blob backend is
	// shared (backendFor returns the same backend for all tenants), so the
	// key is the same path — this exposes the current isolation gap.
	bobTok := mintAccessToken(t, ts, "bob", []string{"rw"})
	code, body := ts.do(t, http.MethodGet, "/rs/docs/secret.txt", "bob.example.com", bobTok, "", nil)
	if code == http.StatusOK && strings.Contains(body, "alice secret") {
		t.Fatalf("ISOLATION GAP: bob read alice's blob (status %d)", code)
	}
}
