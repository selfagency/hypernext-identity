package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// pkcePair returns a valid S256 code_verifier + code_challenge pair.
func pkcePair() (verifier, challenge string) {
	verifier = "verifier12345678901234567890123456789012345678901234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// noRedirectClient returns a client that does not follow redirects, so the
// test can inspect the 302 Location without resolving the redirect target.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// TestIndieAuthAuthorize verifies the IndieAuth authorization endpoint
// redirects with a code.
func TestIndieAuthAuthorizeNoRedirect(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "https://app.example.com/app")
	params.Set("redirect_uri", "https://app.example.com/cb")
	params.Set("state", "abc123")
	params.Set("me", "https://alice.example.com/profile")
	_, challenge := pkcePair()
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	req, err := http.NewRequest(http.MethodGet, ts.baseURL+"/indieauth/auth?"+params.Encode(), http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "id.example.com"
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("indieauth auth status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "code=abc123") {
		t.Fatalf("Location = %q, want code=abc123", loc)
	}
}

// TestIndieAuthToken verifies the token endpoint mints an access token.
func TestIndieAuthToken(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)

	// First get an authorization code.
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "https://app.example.com/app")
	params.Set("redirect_uri", "https://app.example.com/cb")
	params.Set("state", "abc123")
	params.Set("me", "https://alice.example.com/profile")
	_, challenge := pkcePair()
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	req, err := http.NewRequest(http.MethodGet, ts.baseURL+"/indieauth/auth?"+params.Encode(), http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "id.example.com"
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("auth status = %d, want 302", resp.StatusCode)
	}

	// Token exchange.
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", "abc123")
	body.Set("client_id", "https://app.example.com/app")
	body.Set("redirect_uri", "https://app.example.com/cb")
	body.Set("me", "https://alice.example.com/profile")
	verifier, _ := pkcePair()
	body.Set("code_verifier", verifier)

	status, tokenBody := ts.do(t, http.MethodPost, "/indieauth/token", "id.example.com", "", "application/x-www-form-urlencoded", []byte(body.Encode()))
	if status != http.StatusOK {
		t.Fatalf("indieauth token status = %d, want 200 (body %q)", status, tokenBody)
	}
	if !strings.Contains(tokenBody, "access_token") {
		t.Fatalf("indieauth token missing access_token: %q", tokenBody)
	}
}
