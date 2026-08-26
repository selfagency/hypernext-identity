package indieauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.hacdias.com/indielib/indieauth"
)

// fakeIssuer mints tokens for a fixed profile.
type fakeIssuer struct {
	profile string
	token   string
}

func (f fakeIssuer) IssueForProfile(_ context.Context, profileURL string, _ []string) (string, error) {
	if profileURL != f.profile {
		return "", errors.New("profile mismatch")
	}
	return f.token, nil
}

// TestParseAuthorization verifies a valid authorization request parses.
func TestParseAuthorization(t *testing.T) {
	b := NewBridge(true, fakeIssuer{})
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"https://app.example.com/"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"scope":                 {"profile email"},
		"state":                 {"state-1"},
		"code_challenge":        {"a-very-long-pkce-challenge-value-0123456789abcdefghijklmnopqrstuvwxyz"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("POST", "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	authReq, err := b.ParseAuthorization(req)
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	if authReq.ClientID != "https://app.example.com/" {
		t.Fatalf("clientID = %q", authReq.ClientID)
	}
	if len(authReq.Scopes) != 2 || authReq.Scopes[0] != "profile" {
		t.Fatalf("scopes = %v", authReq.Scopes)
	}
	if authReq.State != "state-1" {
		t.Fatalf("state = %q", authReq.State)
	}
}

// TestParseAuthorizationRequiresPKCE verifies PKCE is enforced.
func TestParseAuthorizationRequiresPKCE(t *testing.T) {
	b := NewBridge(true, fakeIssuer{})
	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"https://app.example.com/"},
		"redirect_uri":  {"https://app.example.com/callback"},
	}
	req := httptest.NewRequest("POST", "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := b.ParseAuthorization(req); err == nil {
		t.Fatal("expected PKCE required error")
	}
}

// TestParseAuthorizationRejectsBadRedirect verifies redirect URI validation.
func TestParseAuthorizationRejectsBadRedirect(t *testing.T) {
	b := NewBridge(true, fakeIssuer{})
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"https://app.example.com/"},
		"redirect_uri":          {"https://evil.example.com/callback"},
		"code_challenge":        {"a-very-long-pkce-verifier-value-0123456789abcdefghijklmnopqrstuvwxyz"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("POST", "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := b.ParseAuthorization(req); err == nil {
		t.Fatal("expected redirect URI mismatch error")
	}
}

// TestValidateTokenExchange verifies a valid token exchange.
func TestValidateTokenExchange(t *testing.T) {
	b := NewBridge(true, fakeIssuer{})
	verifier := "a-very-long-pkce-verifier-value-0123456789abcdefghijklmnopqrstuvwxyz"
	authReq := &indieauth.AuthenticationRequest{
		ClientID:            "https://app.example.com/",
		RedirectURI:         "https://app.example.com/callback",
		CodeChallenge:       s256Challenge(verifier),
		CodeChallengeMethod: "S256",
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-1"},
		"client_id":     {"https://app.example.com/"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := b.ValidateTokenExchange(authReq, req); err != nil {
		t.Fatalf("ValidateTokenExchange: %v", err)
	}
}

// s256Challenge computes the S256 code challenge for a verifier.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestValidateTokenExchangeRejectsMismatch verifies client_id mismatch is rejected.
func TestValidateTokenExchangeRejectsMismatch(t *testing.T) {
	b := NewBridge(true, fakeIssuer{})
	authReq := &indieauth.AuthenticationRequest{
		ClientID:    "https://app.example.com/",
		RedirectURI: "https://app.example.com/callback",
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-1"},
		"client_id":    {"https://other.example.com/"},
		"redirect_uri": {"https://app.example.com/callback"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := b.ValidateTokenExchange(authReq, req); err == nil {
		t.Fatal("expected client_id mismatch error")
	}
}

// TestIssueToken verifies token minting for a profile.
func TestIssueToken(t *testing.T) {
	b := NewBridge(true, fakeIssuer{profile: "https://alice.example.com", token: "tok-1"})
	tok, err := b.IssueToken(context.Background(), "https://alice.example.com", []string{"profile"})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("token = %q, want tok-1", tok)
	}
}

// TestIssueTokenRequiresProfile verifies an empty profile is rejected.
func TestIssueTokenRequiresProfile(t *testing.T) {
	b := NewBridge(true, fakeIssuer{})
	if _, err := b.IssueToken(context.Background(), "", nil); err == nil {
		t.Fatal("expected error for empty profile")
	}
}

// TestDiscoverApplicationMetadata verifies h-app discovery.
func TestDiscoverApplicationMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><div class="h-app"><span class="p-name">My App</span></div></body></html>`))
	}))
	defer srv.Close()

	b := NewBridge(true, fakeIssuer{})
	meta, err := b.DiscoverApplicationMetadata(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("DiscoverApplicationMetadata: %v", err)
	}
	if meta.Name != "My App" {
		t.Fatalf("name = %q, want My App", meta.Name)
	}
}
