package auth

import (
	"testing"
	"time"
)

// TestMintAndValidateAccessToken verifies minting and validating a signed
// access token round-trips the subject and scopes.
func TestMintAndValidateAccessToken(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	priv := store.SigningKeyMaterial()

	tok, err := MintAccessToken(priv, "alice", []string{"rw"}, AccessTokenTTL)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	claims, err := ValidateAccessToken(priv, tok)
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

	// Mint with a negative TTL so it is already expired.
	tok, err := MintAccessToken(priv, "alice", []string{"rw"}, -time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	if _, err := ValidateAccessToken(priv, tok); err == nil {
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
	tok, err := MintAccessToken(otherPriv, "alice", []string{"rw"}, AccessTokenTTL)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	if _, err := ValidateAccessToken(priv, tok); err == nil {
		t.Fatal("token signed by foreign key accepted")
	}

	// Garbage token rejected.
	if _, err := ValidateAccessToken(priv, "not-a-jwt"); err == nil {
		t.Fatal("garbage token accepted")
	}

	// Nil key rejected.
	if _, err := ValidateAccessToken(nil, tok); err == nil {
		t.Fatal("nil key accepted")
	}
}
