package authstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hypernext/identity/internal/auth"
	"github.com/hypernext/identity/internal/store"
)

// newTestStore opens a temp SQLite store.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestSigningKeyPersistence verifies the signing key survives a reopen.
func TestSigningKeyPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	// First open: generates + persists a signing key.
	s1, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mem1, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	key1 := mem1.SigningKeyMaterial()
	as1, err := New(ctx, mem1, s1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = as1
	_ = s1.Close()

	// Reopen: should reuse the persisted key (same material).
	s2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	mem2, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	as2, err := New(ctx, mem2, s2)
	if err != nil {
		t.Fatalf("New reopen: %v", err)
	}
	_ = as2
	key2 := mem2.SigningKeyMaterial()
	// Compare key material (N/D), not pointer identity.
	if key1.N.Cmp(key2.N) != 0 || key1.D.Cmp(key2.D) != 0 {
		t.Fatal("signing key changed across reopen — JWTs would break")
	}
}

// TestRefreshTokenHashedAtRest verifies the raw refresh token is never stored
// in the DB — only its SHA-256 hash. A DB read must not yield a replayable
// credential.
func TestRefreshTokenHashedAtRest(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	mem, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	as, err := New(ctx, mem, s)
	if err != nil {
		t.Fatal(err)
	}

	raw := "raw-refresh-token-123"
	if err := as.PersistRefreshToken(ctx, raw, "alice", "client1", []string{"openid"}); err != nil {
		t.Fatalf("PersistRefreshToken: %v", err)
	}

	// The raw token must not be retrievable from the DB.
	if _, err := s.GetAuthRefreshToken(ctx, raw); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("raw token found in DB (err=%v), want ErrNotFound", err)
	}

	// The SHA-256 hash must be present and loadable.
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	got, err := s.GetAuthRefreshToken(ctx, hash)
	if err != nil {
		t.Fatalf("hashed token not found: %v", err)
	}
	if got.Subject != "alice" {
		t.Fatalf("subject = %q, want alice", got.Subject)
	}

	// LoadRefreshToken resolves the raw token via its hash.
	subject, _, _, err := as.LoadRefreshToken(ctx, raw)
	if err != nil || subject != "alice" {
		t.Fatalf("LoadRefreshToken = %q, %v", subject, err)
	}
}

// TestRefreshTokenRoundTrip verifies refresh token persist/load/delete.
func TestRefreshTokenRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	mem, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	as, err := New(ctx, mem, s)
	if err != nil {
		t.Fatal(err)
	}

	if err := as.PersistRefreshToken(ctx, "tok1", "alice", "client1", []string{"openid", "profile"}); err != nil {
		t.Fatalf("PersistRefreshToken: %v", err)
	}
	subject, clientID, scopes, err := as.LoadRefreshToken(ctx, "tok1")
	if err != nil {
		t.Fatalf("LoadRefreshToken: %v", err)
	}
	if subject != "alice" || clientID != "client1" || len(scopes) != 2 {
		t.Fatalf("loaded = %q %q %v", subject, clientID, scopes)
	}

	if err := as.DeleteRefreshToken(ctx, "tok1"); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	if _, _, _, err := as.LoadRefreshToken(ctx, "tok1"); err == nil {
		t.Fatal("expected error after delete")
	}
}
