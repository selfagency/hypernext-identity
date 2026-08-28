// Package authstore implements a SQLite-backed persistence layer for the
// OIDC auth core. It wraps the in-memory MemoryStore and persists the
// durable-critical state — the signing key and refresh tokens — so sessions
// survive restarts. Auth codes are short-lived and stay in memory.
package authstore

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// Store wraps the in-memory auth store with SQLite persistence for the
// signing key and refresh tokens.
type Store struct {
	mem   *auth.MemoryStore
	store *store.Store
}

// SigningKey returns the RSA private signing key used to sign access tokens.
func (s *Store) SigningKey() *rsa.PrivateKey {
	return s.mem.SigningKeyMaterial()
}

// New builds a SQLite-backed auth store. If no signing key is persisted yet,
// it generates one and stores it; otherwise it reuses the persisted key so
// existing JWTs remain verifiable across restarts.
func New(ctx context.Context, mem *auth.MemoryStore, s *store.Store) (*Store, error) {
	// Try to load a persisted signing key.
	key, err := s.GetAuthSigningKey(ctx, "signing-1")
	if err == nil {
		// Reuse the persisted key.
		priv, err := parseRSAPrivate(key.KeyPEM)
		if err != nil {
			return nil, err
		}
		mem.SetSigningKey(priv)
		return &Store{mem: mem, store: s}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	// No persisted key — the MemoryStore already generated one; persist it.
	priv := mem.SigningKeyMaterial()
	pemBytes, err := marshalRSAPrivate(priv)
	if err != nil {
		return nil, err
	}
	if err := s.SaveAuthSigningKey(ctx, store.AuthSigningKey{
		ID:        "signing-1",
		KeyPEM:    string(pemBytes),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}
	return &Store{mem: mem, store: s}, nil
}

// parseRSAPrivate decodes a PEM-encoded RSA private key.
func parseRSAPrivate(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("authstore: invalid PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// marshalRSAPrivate encodes an RSA private key as PEM.
func marshalRSAPrivate(key *rsa.PrivateKey) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), nil
}

// PersistRefreshToken stores a refresh token grant. Only the SHA-256 hash of
// the token is persisted; the raw token is never written to the DB.
func (s *Store) PersistRefreshToken(ctx context.Context, token, subject, clientID string, scopes []string) error {
	return s.store.SaveAuthRefreshToken(ctx, &store.AuthRefreshToken{
		Token:     hashToken(token),
		Subject:   subject,
		ClientID:  clientID,
		Scopes:    strings.Join(scopes, ","),
		AuthTime:  time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
	})
}

// LoadRefreshToken retrieves a refresh token grant by its raw value, looking
// it up by hash. It returns ErrNotFound for unknown tokens and rejects
// expired or revoked tokens.
func (s *Store) LoadRefreshToken(ctx context.Context, token string) (subject, clientID string, scopes []string, err error) {
	t, err := s.store.GetAuthRefreshToken(ctx, hashToken(token))
	if err != nil {
		return "", "", nil, err
	}
	if !t.RevokedAt.IsZero() {
		return "", "", nil, store.ErrNotFound
	}
	if !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) {
		return "", "", nil, store.ErrNotFound
	}
	return t.Subject, t.ClientID, strings.Split(t.Scopes, ","), nil
}

// DeleteRefreshToken removes a refresh token (revocation).
func (s *Store) DeleteRefreshToken(ctx context.Context, token string) error {
	return s.store.DeleteAuthRefreshToken(ctx, hashToken(token))
}

// hashToken returns the hex SHA-256 hash of a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
