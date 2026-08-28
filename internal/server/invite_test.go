package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// testRSAKey returns a fresh RSA key for signing tests.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// seedInviteUser creates a user + invite token and returns the raw token.
func seedInviteUser(t *testing.T, st *store.Store, raw string) *store.User {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateTenant(ctx, &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "u1", TenantID: "identity", Handle: "alice", Email: "a@example.com"}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateInviteToken(ctx, &store.InviteToken{
		ID: "inv1", TokenHash: hashToken(raw), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return u
}

// TestInviteValidToken verifies a valid invite token marks it used, sets a
// session cookie, and redirects to the user panel.
func TestInviteValidToken(t *testing.T) {
	st := newTestStore(t)
	raw := "rawtoken123"
	seedInviteUser(t, st, raw)
	key := testRSAKey(t)

	h := inviteHandler(st, key)
	req := httptest.NewRequest("GET", "/invite/"+raw, http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body %q)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/panel") {
		t.Fatalf("Location = %q, want /panel", loc)
	}
	// Session cookie set.
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie set")
	}
	// Token marked used.
	it, err := st.InviteTokenByHash(context.Background(), hashToken(raw))
	if err != nil {
		t.Fatalf("InviteTokenByHash: %v", err)
	}
	if it.UsedAt.IsZero() {
		t.Fatal("invite token not marked used")
	}
}

// TestInviteUnknownToken verifies an unknown token returns 404.
func TestInviteUnknownToken(t *testing.T) {
	st := newTestStore(t)
	h := inviteHandler(st, testRSAKey(t))
	req := httptest.NewRequest("GET", "/invite/unknown", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestInviteMissingToken verifies an empty token returns 400.
func TestInviteMissingToken(t *testing.T) {
	st := newTestStore(t)
	h := inviteHandler(st, testRSAKey(t))
	req := httptest.NewRequest("GET", "/invite/", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestInviteExpiredToken verifies an expired token returns 410 Gone.
func TestInviteExpiredToken(t *testing.T) {
	st := newTestStore(t)
	raw := "expiredtoken"
	ctx := context.Background()
	if err := st.CreateTenant(ctx, &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &store.User{ID: "u1", TenantID: "identity", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateInviteToken(ctx, &store.InviteToken{
		ID: "inv1", TokenHash: hashToken(raw), UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	h := inviteHandler(st, testRSAKey(t))
	req := httptest.NewRequest("GET", "/invite/"+raw, http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
}

// TestInviteUsedToken verifies a consumed token returns 410 Gone.
func TestInviteUsedToken(t *testing.T) {
	st := newTestStore(t)
	raw := "usedtoken"
	ctx := context.Background()
	if err := st.CreateTenant(ctx, &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &store.User{ID: "u1", TenantID: "identity", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateInviteToken(ctx, &store.InviteToken{
		ID: "inv1", TokenHash: hashToken(raw), UserID: "u1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkInviteTokenUsed(ctx, "inv1"); err != nil {
		t.Fatal(err)
	}

	h := inviteHandler(st, testRSAKey(t))
	req := httptest.NewRequest("GET", "/invite/"+raw, http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
}

// TestInviteSessionCookieValid verifies the session cookie carries a valid
// access token for the invited user.
func TestInviteSessionCookieValid(t *testing.T) {
	st := newTestStore(t)
	raw := "rawtoken456"
	u := seedInviteUser(t, st, raw)
	key := testRSAKey(t)

	h := inviteHandler(st, key)
	req := httptest.NewRequest("GET", "/invite/"+raw, http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var tok string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("no session cookie")
	}
	claims, err := auth.ValidateAccessToken(key, tok)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Subject != u.ID {
		t.Fatalf("session subject = %q, want %q", claims.Subject, u.ID)
	}
}
