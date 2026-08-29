package server

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// seedPanelUser creates a user and returns a valid session cookie value.
func seedPanelUser(t *testing.T, st *store.Store, key *rsa.PrivateKey, tos, passkey bool) (string, *store.User) {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateTenant(ctx, &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "u1", TenantID: "identity", Handle: "alice", Email: "a@example.com", ToSAccepted: tos, PasskeySetup: passkey}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if tos {
		if err := st.SetToSAccepted(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	if passkey {
		if err := st.SetPasskeySetup(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := auth.MintAccessToken(key, u.ID, []string{"self"}, auth.AccessTokenTTL, "https://id.example.com", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	return tok, u
}

// sessionCookieValue returns a session cookie with the security flags set.
func sessionCookieValue(tok string) *http.Cookie {
	return &http.Cookie{Name: sessionCookie, Value: tok, HttpOnly: true, Secure: true, Path: "/"}
}

// TestPanelForcesToS verifies a user who hasn't accepted ToS is shown the ToS
// form, not the profile.
func TestPanelForcesToS(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, _ := seedPanelUser(t, st, key, false, false)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	req := httptest.NewRequest("GET", "/panel", http.NoBody)
	req.AddCookie(sessionCookieValue(tok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Terms of Service") {
		t.Fatalf("panel should show ToS form: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "passkey") {
		t.Fatalf("panel should not show passkey before ToS: %q", rec.Body.String())
	}
}

// TestPanelForcesPasskey verifies a user who accepted ToS but has no passkey
// is shown the passkey setup.
func TestPanelForcesPasskey(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, _ := seedPanelUser(t, st, key, true, false)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	req := httptest.NewRequest("GET", "/panel", http.NoBody)
	req.AddCookie(sessionCookieValue(tok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "passkey") {
		t.Fatalf("panel should show passkey setup: %q", rec.Body.String())
	}
}

// TestPanelShowsProfile verifies a fully onboarded user sees the profile form.
func TestPanelShowsProfile(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, _ := seedPanelUser(t, st, key, true, true)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	req := httptest.NewRequest("GET", "/panel", http.NoBody)
	req.AddCookie(sessionCookieValue(tok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Display name") {
		t.Fatalf("panel should show profile form: %q", rec.Body.String())
	}
}

// TestPanelNoSession verifies a missing/invalid session is rejected.
func TestPanelNoSession(t *testing.T) {
	st := newTestStore(t)
	h := panelHandler(st, testRSAKey(t), "https://id.example.com", "example.com")
	req := httptest.NewRequest("GET", "/panel", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestPanelAcceptToS verifies POST /panel/tos records acceptance.
func TestPanelAcceptToS(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, u := seedPanelUser(t, st, key, false, false)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	form := url.Values{"accept": {"1"}}
	req := httptest.NewRequest("POST", "/panel/tos", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookieValue(tok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	got, _ := st.UserByID(context.Background(), u.ID)
	if !got.ToSAccepted {
		t.Fatal("ToS not recorded")
	}
}

// TestPanelSaveProfile verifies POST /panel/profile saves the profile.
func TestPanelSaveProfile(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, _ := seedPanelUser(t, st, key, true, true)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	form := url.Values{"display_name": {"Alice Updated"}, "bio": {"Hello"}}
	req := httptest.NewRequest("POST", "/panel/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookieValue(tok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	page, err := st.GetProfilePage(context.Background(), "identity")
	if err != nil {
		t.Fatalf("GetProfilePage: %v", err)
	}
	if page.DisplayName != "Alice Updated" || page.Bio != "Hello" {
		t.Fatalf("profile = %+v", page)
	}
}

// TestPanelCompletePasskey verifies POST /panel/passkey marks passkey setup
// complete and redirects to the profile.
func TestPanelCompletePasskey(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, u := seedPanelUser(t, st, key, true, false)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	req := httptest.NewRequest("POST", "/panel/passkey", http.NoBody)
	req.AddCookie(sessionCookieValue(tok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	got, _ := st.UserByID(context.Background(), u.ID)
	if !got.PasskeySetup {
		t.Fatal("passkey setup not recorded")
	}
}

// TestPanelPasskeyRequiresAuth verifies POST /panel/passkey rejects a missing
// session.
func TestPanelPasskeyRequiresAuth(t *testing.T) {
	st := newTestStore(t)
	h := panelHandler(st, testRSAKey(t), "https://id.example.com", "example.com")
	req := httptest.NewRequest("POST", "/panel/passkey", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestPanelEndpointsRejectWrongMethod verifies the panel POST endpoints reject
// non-POST requests.
func TestPanelEndpointsRejectWrongMethod(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, _ := seedPanelUser(t, st, key, true, true)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	for _, path := range []string{"/panel/tos", "/panel/passkey", "/panel/profile"} {
		req := httptest.NewRequest("GET", path, http.NoBody)
		req.AddCookie(sessionCookieValue(tok))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s GET = %d, want 405", path, rec.Code)
		}
	}
}

// TestPanelEndpointsRequireAuth verifies the panel POST endpoints reject a
// missing session.
func TestPanelEndpointsRequireAuth(t *testing.T) {
	st := newTestStore(t)
	h := panelHandler(st, testRSAKey(t), "https://id.example.com", "example.com")

	for _, path := range []string{"/panel/tos", "/panel/passkey", "/panel/profile"} {
		req := httptest.NewRequest("POST", path, http.NoBody)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s = %d, want 401", path, rec.Code)
		}
	}
}

// TestPanelProfileBadForm verifies POST /panel/profile rejects a malformed
// form body.
func TestPanelProfileBadForm(t *testing.T) {
	st := newTestStore(t)
	key := testRSAKey(t)
	tok, _ := seedPanelUser(t, st, key, true, true)
	h := panelHandler(st, key, "https://id.example.com", "example.com")

	req := httptest.NewRequest("POST", "/panel/profile", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookieValue(tok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
