package authstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
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

// TestParseRSAPrivatePKCS8 verifies a PKCS#8-encoded RSA private key is
// accepted in addition to PKCS#1.
func TestParseRSAPrivatePKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	got, err := parseRSAPrivate(pemStr)
	if err != nil {
		t.Fatalf("parseRSAPrivate(PKCS#8): %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Fatal("parsed key modulus mismatch")
	}
}

// TestParseRSAPrivateRejectsWeak verifies keys with a modulus below 2048 bits
// are rejected.
func TestParseRSAPrivateRejectsWeak(t *testing.T) {
	// #nosec G402 -- negative test: verifies the parser rejects a <2048-bit key.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	if _, err := parseRSAPrivate(pemStr); err == nil {
		t.Fatal("weak (<2048-bit) key accepted")
	}
}

// TestParseRSAPrivateRejectsTrailing verifies data after the PEM block is
// rejected.
func TestParseRSAPrivateRejectsTrailing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})) + "\ntrailing garbage\n"
	if _, err := parseRSAPrivate(pemStr); err == nil {
		t.Fatal("trailing data after PEM block accepted")
	}
}

// TestParseRSAPrivateRejectsInvalidPEM verifies a non-PEM string is rejected.
func TestParseRSAPrivateRejectsInvalidPEM(t *testing.T) {
	if _, err := parseRSAPrivate("not a pem block"); err == nil {
		t.Fatal("non-PEM input accepted")
	}
}

// TestParseRSAPrivateRejectsGarbage verifies a PEM block whose bytes are
// neither valid PKCS#1 nor PKCS#8 is rejected.
func TestParseRSAPrivateRejectsGarbage(t *testing.T) {
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("this is not a DER-encoded key"),
	}))
	if _, err := parseRSAPrivate(pemStr); err == nil {
		t.Fatal("garbage DER bytes accepted")
	}
}

// TestParseRSAPrivateRejectsNonRSA verifies a PKCS#8-encoded non-RSA key
// (here an EC key) is rejected.
func TestParseRSAPrivateRejectsNonRSA(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := parseRSAPrivate(pemStr); err == nil {
		t.Fatal("non-RSA PKCS#8 key accepted")
	}
}

// TestSigningKey verifies SigningKey returns the MemoryStore's signing key.
func TestSigningKey(t *testing.T) {
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
	if got := as.SigningKey(); got == nil {
		t.Fatal("SigningKey() = nil")
	} else if got.N.Cmp(mem.SigningKeyMaterial().N) != 0 {
		t.Fatal("SigningKey() does not match MemoryStore key")
	}
}

// TestLoadRefreshTokenRevoked verifies a revoked token is rejected.
func TestLoadRefreshTokenRevoked(t *testing.T) {
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

	raw := "revoked-token"
	if err := as.PersistRefreshToken(ctx, raw, "alice", "client1", []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	// Mark the token revoked directly in the store.
	if err := s.SaveAuthRefreshToken(ctx, &store.AuthRefreshToken{
		Token:     hashToken(raw),
		Subject:   "alice",
		ClientID:  "client1",
		Scopes:    "openid",
		RevokedAt: time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := as.LoadRefreshToken(ctx, raw); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LoadRefreshToken(revoked) err = %v, want ErrNotFound", err)
	}
}

// TestLoadRefreshTokenExpired verifies an expired token is rejected.
func TestLoadRefreshTokenExpired(t *testing.T) {
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

	raw := "expired-token"
	if err := as.PersistRefreshToken(ctx, raw, "alice", "client1", []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	// Set an expiry in the past directly in the store.
	if err := s.SaveAuthRefreshToken(ctx, &store.AuthRefreshToken{
		Token:     hashToken(raw),
		Subject:   "alice",
		ClientID:  "client1",
		Scopes:    "openid",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := as.LoadRefreshToken(ctx, raw); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LoadRefreshToken(expired) err = %v, want ErrNotFound", err)
	}
}

// TestNewClosedStore verifies New propagates a non-ErrNotFound store error
// (here a closed store) instead of silently generating a new key.
func TestNewClosedStore(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	mem, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, mem, s); err == nil {
		t.Fatal("New on closed store = nil, want error")
	}
}
