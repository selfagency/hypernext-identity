package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/mail"
	"github.com/selfagency/sovereign/internal/store"
)

// newTestStore opens an in-memory SQLite store.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// fakeSender captures the last message.
type fakeSender struct {
	msg mail.Message
}

func (f *fakeSender) Send(_ context.Context, m mail.Message) error {
	f.msg = m
	return nil
}

// seedIdentityTenant creates the identity tenant so user FK constraints hold.
func seedIdentityTenant(t *testing.T, st *store.Store) {
	t.Helper()
	if err := st.CreateTenant(context.Background(), &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
}

// TestUserHandlerCreateUser verifies POST /admin/users creates a user, an
// invite token, and sends an email with the magic link.
func TestUserHandlerCreateUser(t *testing.T) {
	st := newTestStore(t)
	seedIdentityTenant(t, st)
	sender := &fakeSender{}
	h := &UserHandler{Store: st, Sender: sender, BaseURL: "https://id.example.com"}

	form := url.Values{
		"email":        {"alice@example.com"},
		"handle":       {"alice"},
		"display_name": {"Alice"},
	}
	req := httptest.NewRequest("POST", "/admin/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %q)", rec.Code, rec.Body.String())
	}

	// User created with email.
	u, err := st.UserByHandle(context.Background(), "identity", "alice")
	if err != nil {
		t.Fatalf("UserByHandle: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", u.Email)
	}

	// Email sent with a magic link.
	if sender.msg.To != "alice@example.com" {
		t.Fatalf("email to = %q, want alice@example.com", sender.msg.To)
	}
	if !strings.Contains(sender.msg.Body, "/invite/") {
		t.Fatalf("email body missing magic link: %q", sender.msg.Body)
	}

	// Invite token persisted (hashed, not raw).
	raw := strings.TrimPrefix(sender.msg.Body[strings.Index(sender.msg.Body, "/invite/")+len("/invite/"):], "\n")
	raw = strings.TrimSpace(raw)
	it, err := st.InviteTokenByHash(context.Background(), hashToken(raw))
	if err != nil {
		t.Fatalf("InviteTokenByHash: %v", err)
	}
	if it.UserID != u.ID {
		t.Fatalf("invite user = %q, want %q", it.UserID, u.ID)
	}
}

// TestUserHandlerMissingFields verifies missing email/handle returns 400.
func TestUserHandlerMissingFields(t *testing.T) {
	st := newTestStore(t)
	seedIdentityTenant(t, st)
	h := &UserHandler{Store: st, Sender: &fakeSender{}, BaseURL: "https://id.example.com"}

	form := url.Values{"email": {"alice@example.com"}} // no handle
	req := httptest.NewRequest("POST", "/admin/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestUserHandlerDuplicate verifies a duplicate handle returns 400.
func TestUserHandlerDuplicate(t *testing.T) {
	st := newTestStore(t)
	seedIdentityTenant(t, st)
	h := &UserHandler{Store: st, Sender: &fakeSender{}, BaseURL: "https://id.example.com"}

	form := url.Values{"email": {"alice@example.com"}, "handle": {"alice"}}
	post := func() int {
		req := httptest.NewRequest("POST", "/admin/users", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(); code != http.StatusCreated {
		t.Fatalf("first create = %d, want 201", code)
	}
	if code := post(); code != http.StatusBadRequest {
		t.Fatalf("duplicate create = %d, want 400", code)
	}
}

// TestUserHandlerMethodNotAllowed verifies non-POST is rejected.
func TestUserHandlerMethodNotAllowed(t *testing.T) {
	st := newTestStore(t)
	h := &UserHandler{Store: st, Sender: &fakeSender{}, BaseURL: "https://id.example.com"}
	req := httptest.NewRequest("GET", "/admin/users", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
