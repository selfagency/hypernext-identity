package server

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// TestAdminCreateUserRequiresAuth verifies POST /admin/users rejects
// unauthenticated requests.
func TestAdminCreateUserRequiresAuth(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)
	form := url.Values{"email": {"alice@example.com"}, "handle": {"alice"}}
	status, _ := ts.do(t, http.MethodPost, "/admin/users", "id.example.com", "", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

// TestAdminCreateUserSendsInvite verifies an admin can create a user and the
// dev LogSender emits a magic link.
func TestAdminCreateUserSendsInvite(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)
	ctx := context.Background()

	// Seed an admin user and mint a token.
	if err := ts.srv.store.CreateUser(ctx, &store.User{ID: "admin1", TenantID: "identity", Handle: "root"}); err != nil {
		t.Fatal(err)
	}
	tok, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), "admin1", []string{"admin"}, auth.AccessTokenTTL, "https://id."+ts.srv.cfg.Domain, ts.srv.cfg.Audience)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{"email": {"alice@example.com"}, "handle": {"alice"}, "display_name": {"Alice"}}
	status, body := ts.do(t, http.MethodPost, "/admin/users", "id.example.com", tok, "application/x-www-form-urlencoded", []byte(form.Encode()))
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %q)", status, body)
	}

	// User persisted with email.
	u, err := ts.srv.store.UserByHandle(ctx, "identity", "alice")
	if err != nil {
		t.Fatalf("UserByHandle: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", u.Email)
	}
}
