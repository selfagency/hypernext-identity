package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/selfagency/sovereign/internal/store"
)

// newHandlerTestStore opens a temp store with a seeded identity tenant and
// user.
func newHandlerTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &store.User{ID: "u1", TenantID: "identity", Handle: "alice", DisplayName: "Alice"}); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestWebAuthnHandlerRegisterBegin verifies the register-begin happy path
// returns creation options for a known user.
func TestWebAuthnHandlerRegisterBegin(t *testing.T) {
	st := newHandlerTestStore(t)
	h, err := NewWebAuthnHandler("id.example.com", "Sovereign", "https://id.example.com", st)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/webauthn/register/begin?handle=alice", http.NoBody)
	rec := httptest.NewRecorder()
	h.RegisterBegin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "challenge") {
		t.Fatalf("body missing challenge: %q", rec.Body.String())
	}
}

// TestWebAuthnHandlerLoginBegin verifies login-begin for a user with no
// credentials is rejected (you cannot log in before registering).
func TestWebAuthnHandlerLoginBegin(t *testing.T) {
	st := newHandlerTestStore(t)
	h, err := NewWebAuthnHandler("id.example.com", "Sovereign", "https://id.example.com", st)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/webauthn/login/begin?handle=alice", http.NoBody)
	rec := httptest.NewRecorder()
	h.LoginBegin(rec, req)

	// No credentials registered yet -> begin login fails.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestWebAuthnHandlerFinishNoSession verifies finish without a begin session
// is rejected.
func TestWebAuthnHandlerFinishNoSession(t *testing.T) {
	st := newHandlerTestStore(t)
	h, err := NewWebAuthnHandler("id.example.com", "Sovereign", "https://id.example.com", st)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish?handle=alice", http.NoBody)
	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestWebAuthnHandlerUnknownUser verifies an unknown user is rejected.
func TestWebAuthnHandlerUnknownUser(t *testing.T) {
	st := newHandlerTestStore(t)
	h, err := NewWebAuthnHandler("id.example.com", "Sovereign", "https://id.example.com", st)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/webauthn/register/begin?handle=nobody", http.NoBody)
	rec := httptest.NewRecorder()
	h.RegisterBegin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestSessionStorePutGet verifies put/get round-trip.
func TestSessionStorePutGet(t *testing.T) {
	s := NewSessionStore(time.Minute)
	s.Put("ch1", &webauthn.SessionData{Challenge: "ch1"})
	got, ok := s.Get("ch1")
	if !ok || got.Challenge != "ch1" {
		t.Fatalf("get = %v, %v", got, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("unknown challenge returned")
	}
}

// TestSessionStoreExpiry verifies expired sessions are evicted.
func TestSessionStoreExpiry(t *testing.T) {
	s := NewSessionStore(-time.Second) // already expired
	s.Put("ch1", &webauthn.SessionData{Challenge: "ch1"})
	if _, ok := s.Get("ch1"); ok {
		t.Fatal("expired session returned")
	}
}

// TestSessionStoreDelete verifies Delete removes a session.
func TestSessionStoreDelete(t *testing.T) {
	s := NewSessionStore(time.Minute)
	s.Put("ch1", &webauthn.SessionData{Challenge: "ch1"})
	s.Delete("ch1")
	if _, ok := s.Get("ch1"); ok {
		t.Fatal("deleted session still present")
	}
}
