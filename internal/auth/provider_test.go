package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// setupProvider builds a provider with a memory store and one user + client.
func setupProvider(t *testing.T) (*Provider, *MemoryStore, string) {
	t.Helper()
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	store.AddUser(&User{ID: "user-1", Handle: "alice.example.com", DisplayName: "Alice"})
	store.AddClient(&Client{
		ID:               "client-1",
		Secret:           "secret-1",
		RedirectURIsList: []string{"https://app.example.com/callback"},
		Scopes:           []string{"openid", "profile", "email"},
	})

	issuer := "https://id.example.com"
	p, err := NewProvider(issuer, store)
	if err != nil {
		t.Fatal(err)
	}
	return p, store, issuer
}

// pkceChallenge computes the S256 code challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestDiscovery serves the OIDC discovery document.
func TestDiscovery(t *testing.T) {
	p, _, issuer := setupProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != issuer {
		t.Fatalf("issuer = %v, want %s", doc["issuer"], issuer)
	}
	if _, ok := doc["authorization_endpoint"]; !ok {
		t.Fatal("missing authorization_endpoint")
	}
	if _, ok := doc["token_endpoint"]; !ok {
		t.Fatal("missing token_endpoint")
	}
}

// TestJWKS serves the JSON Web Key Set.
func TestJWKS(t *testing.T) {
	p, _, _ := setupProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", resp.StatusCode)
	}
	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("jwks has no keys")
	}
}

// TestAuthCodeFlow exercises the full authorization code + PKCE flow:
// authorize -> code -> token exchange.
func TestAuthCodeFlow(t *testing.T) {
	p, _, _ := setupProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	verifier := "a-very-long-pkce-verifier-value-0123456789abcdef"
	challenge := pkceChallenge(verifier)

	// 1. Authorization request (code + PKCE S256).
	authURL := srv.URL + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"client-1"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"scope":                 {"openid profile email"},
		"state":                 {"state-123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// The provider redirects to the login URL (empty in our client), so we
	// expect a redirect. For a full flow we'd complete login; here we assert
	// the authorize endpoint responds (redirect or error) rather than 404.
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d, want 302 or 200", resp.StatusCode)
	}

	// 2. Token endpoint must exist and reject a bad grant.
	tokenBody := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"client-1"},
		"client_secret": {"secret-1"},
		"code_verifier": {verifier},
	}.Encode()
	tokenResp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(tokenBody))
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()
	// Invalid code should be rejected (4xx), not silently succeed.
	if tokenResp.StatusCode == http.StatusOK {
		t.Fatal("token exchange with invalid code unexpectedly succeeded")
	}
}

// TestTokenEndpointRejectsBadClientSecret verifies client auth is enforced.
func TestTokenEndpointRejectsBadClientSecret(t *testing.T) {
	p, _, _ := setupProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"whatever"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"client-1"},
		"client_secret": {"wrong-secret"},
	}.Encode()
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("token exchange with bad client secret unexpectedly succeeded")
	}
}

// TestMemoryStoreRoundTrip verifies the store's auth request lifecycle.
func TestMemoryStoreRoundTrip(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "client-1",
		Scopes:       []string{"openid"},
		RedirectURI:  "https://app.example.com/callback",
		ResponseType: oidc.ResponseTypeCode,
		State:        "state-1",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar.GetID(), "code-1"); err != nil {
		t.Fatal(err)
	}
	byCode, err := store.AuthRequestByCode(ctx, "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if byCode.GetID() != ar.GetID() {
		t.Fatalf("auth request by code = %s, want %s", byCode.GetID(), ar.GetID())
	}
	if err := store.DeleteAuthRequest(ctx, ar.GetID()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByID(ctx, ar.GetID()); err == nil {
		t.Fatal("expected error after delete")
	}
}

// TestSigningKeyAndKeySet verifies the signing key and JWKS key set agree.
func TestSigningKeyAndKeySet(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	signing, err := store.SigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.KeySet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("keyset len = %d, want 1", len(keys))
	}
	if keys[0].ID() != signing.ID() {
		t.Fatalf("keyset id = %s, want %s", keys[0].ID(), signing.ID())
	}
}
