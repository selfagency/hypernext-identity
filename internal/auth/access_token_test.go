package auth

import (
	"crypto/rsa"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// testIssuer and testAudience are the expected iss/aud used across the auth
// package tests.
const (
	testIssuer   = "https://id.example.com"
	testAudience = "sovereign"
)

// signToken signs an AccessToken claim set with the given key and JWT typ
// header, returning the serialized token. It is a test helper for building
// tokens with arbitrary (including invalid) claims.
func signToken(t *testing.T, priv *rsa.PrivateKey, claims *AccessToken, typ string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	s, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return s
}

// validClaims returns a claim set that passes all validation checks.
func validClaims() AccessToken {
	return AccessToken{
		Subject:  "alice",
		Scopes:   []string{"rw"},
		Issuer:   testIssuer,
		Audience: testAudience,
		Expiry:   time.Now().Add(time.Hour).Unix(),
		IssuedAt: time.Now().Unix(),
		ID:       "jti-1",
	}
}

// TestIssueForProfile verifies IssueForProfile mints a token for a profile URL.
func TestIssueForProfile(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	tok, err := IssueForProfile(priv, "https://alice.example.com/profile", []string{"read"}, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("IssueForProfile: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	claims, err := ValidateAccessToken(priv, tok, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Subject != "https://alice.example.com/profile" {
		t.Fatalf("subject = %q, want the profile URL", claims.Subject)
	}
}

// TestIssueForProfileEmptyURL verifies an empty profile URL errors.
func TestIssueForProfileEmptyURL(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueForProfile(store.SigningKeyMaterial(), "", nil, testIssuer, testAudience); err == nil {
		t.Fatal("expected error for empty profile URL")
	}
}

// TestMintAndValidateAccessToken verifies minting and validating a signed
// access token round-trips the subject and scopes.
func TestMintAndValidateAccessToken(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	tok, err := MintAccessToken(priv, "alice", []string{"rw"}, AccessTokenTTL, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	claims, err := ValidateAccessToken(priv, tok, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Subject != "alice" {
		t.Fatalf("subject = %q, want alice", claims.Subject)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "rw" {
		t.Fatalf("scopes = %v, want [rw]", claims.Scopes)
	}
}

// TestValidateAccessTokenExpired verifies an expired token is rejected.
func TestValidateAccessTokenExpired(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	claims := validClaims()
	claims.Expiry = time.Now().Add(-time.Minute).Unix()
	tok := signToken(t, priv, &claims, "JWT")
	if _, err := ValidateAccessToken(priv, tok, testIssuer, testAudience); err == nil {
		t.Fatal("expired token accepted")
	}
}

// TestValidateAccessTokenInvalid verifies a tampered/foreign token is
// rejected.
func TestValidateAccessTokenInvalid(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	// A token signed by a different key must be rejected.
	other, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	otherPriv := other.SigningKeyMaterial()
	tok, err := MintAccessToken(otherPriv, "alice", []string{"rw"}, AccessTokenTTL, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	if _, err := ValidateAccessToken(priv, tok, testIssuer, testAudience); err == nil {
		t.Fatal("token signed by foreign key accepted")
	}

	// Garbage token rejected.
	if _, err := ValidateAccessToken(priv, "not-a-jwt", testIssuer, testAudience); err == nil {
		t.Fatal("garbage token accepted")
	}

	// Nil key rejected.
	if _, err := ValidateAccessToken(nil, tok, testIssuer, testAudience); err == nil {
		t.Fatal("nil key accepted")
	}
}

// TestValidateAccessTokenRejectsClaims is a table-driven negative test: each
// rejected claim (exp=0, expired, empty sub, wrong iss, wrong aud, wrong
// token-type) must be rejected by ValidateAccessToken.
func TestValidateAccessTokenRejectsClaims(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	cases := []struct {
		name  string
		token string
	}{
		{"exp zero", signToken(t, priv, func() *AccessToken {
			c := validClaims()
			c.Expiry = 0
			return &c
		}(), "JWT")},
		{"expired", signToken(t, priv, func() *AccessToken {
			c := validClaims()
			c.Expiry = time.Now().Add(-time.Minute).Unix()
			return &c
		}(), "JWT")},
		{"empty sub", signToken(t, priv, func() *AccessToken {
			c := validClaims()
			c.Subject = ""
			return &c
		}(), "JWT")},
		{"wrong iss", signToken(t, priv, func() *AccessToken {
			c := validClaims()
			c.Issuer = "https://evil.example.com"
			return &c
		}(), "JWT")},
		{"wrong aud", signToken(t, priv, func() *AccessToken {
			c := validClaims()
			c.Audience = "other-audience"
			return &c
		}(), "JWT")},
		{"wrong token-type", signToken(t, priv, func() *AccessToken {
			c := validClaims()
			return &c
		}(), "at+jwt")},
	}

	for _, c := range cases {
		if _, err := ValidateAccessToken(priv, c.token, testIssuer, testAudience); err == nil {
			t.Errorf("%s: token accepted, want rejection", c.name)
		}
	}
}

// TestMintAccessTokenRejectsTTL verifies minting with ttl<=0 returns an error.
func TestMintAccessTokenRejectsTTL(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	for _, ttl := range []time.Duration{0, -time.Minute} {
		if _, err := MintAccessToken(priv, "alice", []string{"rw"}, ttl, testIssuer, testAudience); err == nil {
			t.Errorf("ttl=%v: expected error", ttl)
		}
	}
}

// TestMintAccessTokenHasJTI verifies every minted token carries a jti claim.
func TestMintAccessTokenHasJTI(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	for i := 0; i < 5; i++ {
		tok, err := MintAccessToken(priv, "alice", []string{"rw"}, AccessTokenTTL, testIssuer, testAudience)
		if err != nil {
			t.Fatalf("MintAccessToken: %v", err)
		}
		claims, err := ValidateAccessToken(priv, tok, testIssuer, testAudience)
		if err != nil {
			t.Fatalf("ValidateAccessToken: %v", err)
		}
		if claims.ID == "" {
			t.Fatal("minted token missing jti")
		}
	}
}
