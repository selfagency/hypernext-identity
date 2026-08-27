package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestAuthSigningKeyCRUD verifies signing key save/get.
func TestAuthSigningKeyCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	k := AuthSigningKey{ID: "signing-1", KeyPEM: "test-key-material", CreatedAt: time.Now()}
	if err := s.SaveAuthSigningKey(ctx, k); err != nil {
		t.Fatalf("SaveAuthSigningKey: %v", err)
	}

	got, err := s.GetAuthSigningKey(ctx, "signing-1")
	if err != nil {
		t.Fatalf("GetAuthSigningKey: %v", err)
	}
	if got.KeyPEM != k.KeyPEM {
		t.Fatalf("key_pem = %q, want %q", got.KeyPEM, k.KeyPEM)
	}

	// Missing key -> ErrNotFound.
	if _, err := s.GetAuthSigningKey(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}

// TestAuthSigningKeyUpsert verifies save is idempotent by ID.
func TestAuthSigningKeyUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_ = s.SaveAuthSigningKey(ctx, AuthSigningKey{ID: "signing-1", KeyPEM: "key1", CreatedAt: time.Now()})
	_ = s.SaveAuthSigningKey(ctx, AuthSigningKey{ID: "signing-1", KeyPEM: "key2", CreatedAt: time.Now()})

	got, _ := s.GetAuthSigningKey(ctx, "signing-1")
	if got.KeyPEM != "key2" {
		t.Fatalf("key_pem = %q, want key2 (upsert)", got.KeyPEM)
	}
}

// TestAuthRefreshTokenCRUD verifies refresh token save/get/delete.
func TestAuthRefreshTokenCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	tok := &AuthRefreshToken{Token: "tok1", Subject: "alice", ClientID: "client1", Scopes: "openid,profile", AuthTime: time.Now(), CreatedAt: time.Now()}
	if err := s.SaveAuthRefreshToken(ctx, tok); err != nil {
		t.Fatalf("SaveAuthRefreshToken: %v", err)
	}

	got, err := s.GetAuthRefreshToken(ctx, "tok1")
	if err != nil {
		t.Fatalf("GetAuthRefreshToken: %v", err)
	}
	if got.Subject != "alice" || got.ClientID != "client1" || got.Scopes != "openid,profile" {
		t.Fatalf("got = %+v", got)
	}

	// Missing -> ErrNotFound.
	if _, err := s.GetAuthRefreshToken(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}

	// Delete.
	if err := s.DeleteAuthRefreshToken(ctx, "tok1"); err != nil {
		t.Fatalf("DeleteAuthRefreshToken: %v", err)
	}
	if _, err := s.GetAuthRefreshToken(ctx, "tok1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

// TestAuthRefreshTokenReplace verifies save is upsert by token.
func TestAuthRefreshTokenReplace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "tok1", Subject: "alice", ClientID: "c1", Scopes: "openid", AuthTime: time.Now(), CreatedAt: time.Now()})
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "tok1", Subject: "bob", ClientID: "c2", Scopes: "profile", AuthTime: time.Now(), CreatedAt: time.Now()})

	got, _ := s.GetAuthRefreshToken(ctx, "tok1")
	if got.Subject != "bob" {
		t.Fatalf("subject = %q, want bob (replace)", got.Subject)
	}
}
