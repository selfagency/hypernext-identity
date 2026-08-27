package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AuthSigningKey is a persisted OIDC signing key.
type AuthSigningKey struct {
	ID        string
	KeyPEM    string // PEM-encoded RSA private key
	CreatedAt time.Time
}

// AuthRefreshToken is a persisted refresh token grant. The Token field holds
// the SHA-256 hash of the raw token, never the raw token itself.
type AuthRefreshToken struct {
	Token     string
	Subject   string
	ClientID  string
	Scopes    string // comma-joined
	AuthTime  time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
	CreatedAt time.Time
}

// SaveAuthSigningKey persists the signing key (idempotent by ID).
func (s *Store) SaveAuthSigningKey(ctx context.Context, k AuthSigningKey) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_signing_keys (id, key_pem, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET key_pem = excluded.key_pem`,
		k.ID, k.KeyPEM, k.CreatedAt)
	return err
}

// GetAuthSigningKey returns the signing key by ID.
func (s *Store) GetAuthSigningKey(ctx context.Context, id string) (*AuthSigningKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, key_pem, created_at FROM auth_signing_keys WHERE id = ?`, id)
	var k AuthSigningKey
	err := row.Scan(&k.ID, &k.KeyPEM, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &k, err
}

// SaveAuthRefreshToken persists a refresh token grant.
func (s *Store) SaveAuthRefreshToken(ctx context.Context, t *AuthRefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO auth_refresh_tokens (token, subject, client_id, scopes, auth_time, expires_at, revoked_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.Token, t.Subject, t.ClientID, t.Scopes, t.AuthTime, nullableTime(t.ExpiresAt), nullableTime(t.RevokedAt), t.CreatedAt)
	return err
}

// GetAuthRefreshToken returns a refresh token grant.
func (s *Store) GetAuthRefreshToken(ctx context.Context, token string) (*AuthRefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token, subject, client_id, scopes, auth_time, expires_at, revoked_at, created_at FROM auth_refresh_tokens WHERE token = ?`, token)
	var t AuthRefreshToken
	var exp, rev sql.NullTime
	err := row.Scan(&t.Token, &t.Subject, &t.ClientID, &t.Scopes, &t.AuthTime, &exp, &rev, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	t.ExpiresAt = exp.Time
	t.RevokedAt = rev.Time
	return &t, err
}

// DeleteAuthRefreshToken removes a refresh token (revocation).
func (s *Store) DeleteAuthRefreshToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_refresh_tokens WHERE token = ?`, token)
	return err
}
