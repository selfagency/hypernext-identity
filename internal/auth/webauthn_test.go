package auth

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// TestNewWebAuthn validates config and builds a relying party.
func TestNewWebAuthn(t *testing.T) {
	wa, err := NewWebAuthn("id.example.com", "Sovereign", "https://id.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if wa == nil {
		t.Fatal("expected non-nil WebAuthn")
	}
}

// TestSessionCodecRoundTrip verifies session serialization survives a round trip.
func TestSessionCodecRoundTrip(t *testing.T) {
	codec := SessionCodec{}
	orig := &webauthn.SessionData{
		Challenge:            "challenge-abc",
		UserID:               []byte("user-1"),
		AllowedCredentialIDs: [][]byte{[]byte("cred-1")},
		Expires:              time.Unix(1234567890, 0),
		UserVerification:     "required",
	}
	enc, err := codec.Encode(orig)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := codec.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Challenge != orig.Challenge {
		t.Fatalf("challenge = %q, want %q", dec.Challenge, orig.Challenge)
	}
	if !bytes.Equal(dec.UserID, orig.UserID) {
		t.Fatalf("userID = %q, want %q", dec.UserID, orig.UserID)
	}
	if len(dec.AllowedCredentialIDs) != 1 || string(dec.AllowedCredentialIDs[0]) != "cred-1" {
		t.Fatalf("allowedCredentialIDs = %v, want [cred-1]", dec.AllowedCredentialIDs)
	}
}

// TestSessionCodecRejectsGarbage verifies decode fails on invalid input.
func TestSessionCodecRejectsGarbage(t *testing.T) {
	codec := SessionCodec{}
	if _, err := codec.Decode([]byte("not-json")); err == nil {
		t.Fatal("expected error decoding garbage")
	}
}

// TestWebAuthnUserAdapter verifies the User interface adapter.
func TestWebAuthnUserAdapter(t *testing.T) {
	u := &User{ID: "user-1", Handle: "alice.example.com", DisplayName: "Alice"}
	wu := &webauthnUser{u: u}
	if string(wu.WebAuthnID()) != "user-1" {
		t.Fatalf("WebAuthnID = %q, want user-1", wu.WebAuthnID())
	}
	if wu.WebAuthnName() != "alice.example.com" {
		t.Fatalf("WebAuthnName = %q, want alice.example.com", wu.WebAuthnName())
	}
	if wu.WebAuthnDisplayName() != "Alice" {
		t.Fatalf("WebAuthnDisplayName = %q, want Alice", wu.WebAuthnDisplayName())
	}
	if len(wu.WebAuthnCredentials()) != 0 {
		t.Fatalf("expected no credentials, got %d", len(wu.WebAuthnCredentials()))
	}
}
