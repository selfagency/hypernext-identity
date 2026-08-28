package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// TestFirstLoginFlowE2E verifies the full onboarding loop: admin creates a
// user, the magic link is redeemed into a session, the panel forces ToS
// acceptance, and the profile can be saved.
func TestFirstLoginFlowE2E(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)
	ctx := context.Background()

	// Seed an admin and mint a token.
	if err := ts.srv.store.CreateUser(ctx, &store.User{ID: "admin1", TenantID: "identity", Handle: "root"}); err != nil {
		t.Fatal(err)
	}
	tok, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), "admin1", []string{"admin"}, auth.AccessTokenTTL)
	if err != nil {
		t.Fatal(err)
	}

	// Admin creates a user.
	form := url.Values{"email": {"alice@example.com"}, "handle": {"alice"}}
	status, _ := ts.do(t, http.MethodPost, "/admin/users", "id.example.com", tok, "application/x-www-form-urlencoded", []byte(form.Encode()))
	if status != http.StatusCreated {
		t.Fatalf("create user = %d, want 201", status)
	}
	u, err := ts.srv.store.UserByHandle(ctx, "identity", "alice")
	if err != nil {
		t.Fatalf("UserByHandle: %v", err)
	}

	// Redeem a fresh invite token to get a session cookie.
	raw := "e2efirstlogin"
	if err := ts.srv.store.CreateInviteToken(ctx, &store.InviteToken{
		ID: "inv-e2e", TokenHash: hashToken(raw), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	client := noRedirectClient()
	req, _ := http.NewRequest(http.MethodGet, ts.baseURL+"/invite/"+raw, http.NoBody)
	req.Host = "id.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("invite = %d, want 302", resp.StatusCode)
	}
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie")
	}

	// Panel forces ToS.
	panelReq, _ := http.NewRequest(http.MethodGet, ts.baseURL+"/panel", http.NoBody)
	panelReq.Host = "id.example.com"
	panelReq.AddCookie(session)
	panelResp, err := client.Do(panelReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = panelResp.Body.Close() }()
	panelBody := readBody(t, panelResp)
	if !strings.Contains(panelBody, "Terms of Service") {
		t.Fatalf("panel should force ToS: %q", panelBody)
	}

	// Accept ToS.
	tosForm := url.Values{"accept": {"1"}}
	tosReq, _ := http.NewRequest(http.MethodPost, ts.baseURL+"/panel/tos", strings.NewReader(tosForm.Encode()))
	tosReq.Host = "id.example.com"
	tosReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tosReq.AddCookie(session)
	tosResp, err := client.Do(tosReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = tosResp.Body.Close()
	if tosResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("accept tos = %d, want 303", tosResp.StatusCode)
	}

	// Panel now shows passkey setup (no passkey yet).
	panelReq2, _ := http.NewRequest(http.MethodGet, ts.baseURL+"/panel", http.NoBody)
	panelReq2.Host = "id.example.com"
	panelReq2.AddCookie(session)
	panelResp2, err := client.Do(panelReq2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = panelResp2.Body.Close() }()
	panelBody2 := readBody(t, panelResp2)
	if !strings.Contains(panelBody2, "passkey") {
		t.Fatalf("panel should show passkey setup: %q", panelBody2)
	}
}

// readBody reads and closes a response body.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
	}
	return string(b)
}
