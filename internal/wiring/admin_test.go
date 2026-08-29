package wiring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// newAdminTestStore opens a temp store with an identity tenant and two users
// (one admin, one not).
func newAdminTestStore(t *testing.T) (*store.Store, *auth.SQLStore) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateTenant(ctx, &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	// First user is admin.
	if err := st.CreateUser(ctx, &store.User{ID: "admin1", TenantID: "identity", Handle: "root"}); err != nil {
		t.Fatal(err)
	}
	// Second user is not admin.
	if err := st.CreateUser(ctx, &store.User{ID: "user1", TenantID: "identity", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	as, err := auth.NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	return st, as
}

// mintToken mints a signed access token for the given subject.
func mintToken(t *testing.T, as *auth.SQLStore, subject string) string {
	t.Helper()
	tok, err := auth.MintAccessToken(as.SigningKeyMaterial(), subject, []string{"admin"}, auth.AccessTokenTTL, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestAdminGuardAdmin verifies an admin token authorizes.
func TestAdminGuardAdmin(t *testing.T) {
	st, as := newAdminTestStore(t)
	guard := &AdminGuard{Key: as.SigningKeyMaterial(), Store: st, Issuer: testIssuer, Audience: testAudience}
	tok := mintToken(t, as, "admin1")

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	if !guard.Authorize(req) {
		t.Fatal("admin token rejected")
	}
}

// TestAdminGuardNonAdmin verifies a non-admin token is rejected.
func TestAdminGuardNonAdmin(t *testing.T) {
	st, as := newAdminTestStore(t)
	guard := &AdminGuard{Key: as.SigningKeyMaterial(), Store: st, Issuer: testIssuer, Audience: testAudience}
	tok := mintToken(t, as, "user1")

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	if guard.Authorize(req) {
		t.Fatal("non-admin token accepted")
	}
}

// TestAdminGuardNoToken verifies a missing token is rejected.
func TestAdminGuardNoToken(t *testing.T) {
	st, as := newAdminTestStore(t)
	guard := &AdminGuard{Key: as.SigningKeyMaterial(), Store: st, Issuer: testIssuer, Audience: testAudience}

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	if guard.Authorize(req) {
		t.Fatal("no-token request accepted")
	}
}

// TestAdminGuardUnknownUser verifies a token for an unknown user is rejected.
func TestAdminGuardUnknownUser(t *testing.T) {
	st, as := newAdminTestStore(t)
	guard := &AdminGuard{Key: as.SigningKeyMaterial(), Store: st, Issuer: testIssuer, Audience: testAudience}
	tok := mintToken(t, as, "ghost")

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	if guard.Authorize(req) {
		t.Fatal("unknown-user token accepted")
	}
}

// TestAdminGuardMiddleware verifies the middleware rejects non-admins with 401.
func TestAdminGuardMiddleware(t *testing.T) {
	st, as := newAdminTestStore(t)
	guard := &AdminGuard{Key: as.SigningKeyMaterial(), Store: st, Issuer: testIssuer, Audience: testAudience}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No token -> 401.
	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	rec := httptest.NewRecorder()
	guard.Middleware(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", rec.Code)
	}

	// Admin token -> 200.
	tok := mintToken(t, as, "admin1")
	req2 := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	guard.Middleware(next).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200", rec2.Code)
	}
}
