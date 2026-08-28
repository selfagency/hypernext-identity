package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

// GetAuthRefreshTokenByHash returns a refresh token grant by its hashed value.
func (s *Store) GetAuthRefreshTokenByHash(ctx context.Context, hash string) (subject, clientID string, scopes []string, err error) {
	t, err := s.GetAuthRefreshToken(ctx, hash)
	if err != nil {
		return "", "", nil, err
	}
	if !t.RevokedAt.IsZero() {
		return "", "", nil, ErrNotFound
	}
	if !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) {
		return "", "", nil, ErrNotFound
	}
	return t.Subject, t.ClientID, splitCSV(t.Scopes), nil
}

// DeleteAuthRefreshToken removes a refresh token (revocation).
func (s *Store) DeleteAuthRefreshToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_refresh_tokens WHERE token = ?`, token)
	return err
}

// User is an OIDC/WebAuthn subject that can authenticate and hold passkeys.
type User struct {
	ID           string
	TenantID     string
	Handle       string
	DisplayName  string
	Email        string
	IsAdmin      bool
	ToSAccepted  bool
	PasskeySetup bool
	CreatedAt    time.Time
}

// Client is an OIDC relying party registered with the provider.
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	Scopes       []string
	CreatedAt    time.Time
}

// WebAuthnCredential is a stored passkey for a user.
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Data         []byte // full go-webauthn Credential JSON
	CreatedAt    time.Time
}

// AuditEntry is a single row in the persistent audit log.
type AuditEntry struct {
	ID        string
	TenantID  string
	Actor     string
	Action    string
	Target    string
	Detail    string
	CreatedAt time.Time
}

// ErrDuplicateUser is returned when a user already exists for a tenant+handle.
var ErrDuplicateUser = errors.New("store: user already exists")

// ErrDuplicateClient is returned when a client ID already exists.
var ErrDuplicateClient = errors.New("store: client already exists")

// CreateUser inserts a user. The first user in the store becomes the instance
// admin (is_admin = 1); subsequent users default to non-admin unless the
// caller sets IsAdmin explicitly.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	// The first user in the store is the instance admin.
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("store: count users: %w", err)
	}
	isAdmin := u.IsAdmin
	if count == 0 {
		isAdmin = true
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, tenant_id, handle, display_name, email, is_admin) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.TenantID, u.Handle, u.DisplayName, u.Email, isAdmin)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrDuplicateUser
		}
		return fmt.Errorf("store: create user: %w", err)
	}
	u.IsAdmin = isAdmin
	return nil
}

// UserByHandle returns a user by tenant + handle.
func (s *Store) UserByHandle(ctx context.Context, tenantID, handle string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, handle, display_name, email, is_admin, tos_accepted, passkey_setup, created_at FROM users WHERE tenant_id = ? AND handle = ?`,
		tenantID, handle)
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Handle, &u.DisplayName, &u.Email, &u.IsAdmin, &u.ToSAccepted, &u.PasskeySetup, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// UserByID returns a user by ID.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, handle, display_name, email, is_admin, tos_accepted, passkey_setup, created_at FROM users WHERE id = ?`, id)
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Handle, &u.DisplayName, &u.Email, &u.IsAdmin, &u.ToSAccepted, &u.PasskeySetup, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// ListUsers returns all users for a tenant.
func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, handle, display_name, email, is_admin, tos_accepted, passkey_setup, created_at FROM users WHERE tenant_id = ? ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Handle, &u.DisplayName, &u.Email, &u.IsAdmin, &u.ToSAccepted, &u.PasskeySetup, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserAdmin toggles a user's admin flag.
func (s *Store) SetUserAdmin(ctx context.Context, id string, isAdmin bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET is_admin = ? WHERE id = ?`, isAdmin, id)
	if err != nil {
		return fmt.Errorf("store: set user admin: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserEmail sets a user's email address.
func (s *Store) SetUserEmail(ctx context.Context, id, email string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ?`, email, id)
	if err != nil {
		return fmt.Errorf("store: set user email: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetToSAccepted records that a user accepted the Terms of Service.
func (s *Store) SetToSAccepted(ctx context.Context, id string, accepted bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET tos_accepted = ? WHERE id = ?`, accepted, id)
	if err != nil {
		return fmt.Errorf("store: set tos accepted: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPasskeySetup records whether a user has completed passkey setup.
func (s *Store) SetPasskeySetup(ctx context.Context, id string, done bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET passkey_setup = ? WHERE id = ?`, done, id)
	if err != nil {
		return fmt.Errorf("store: set passkey setup: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// InviteToken is a one-time magic-link token for user onboarding.
// TokenHash holds the SHA-256 hash of the raw token, never the raw token.
type InviteToken struct {
	ID        string
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

// CreateInviteToken persists a hashed invite token.
func (s *Store) CreateInviteToken(ctx context.Context, t *InviteToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invite_tokens (id, token_hash, user_id, expires_at) VALUES (?, ?, ?, ?)`,
		t.ID, t.TokenHash, t.UserID, t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: create invite token: %w", err)
	}
	return nil
}

// InviteTokenByHash returns an invite token by its hashed value.
func (s *Store) InviteTokenByHash(ctx context.Context, hash string) (*InviteToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token_hash, user_id, created_at, expires_at, used_at FROM invite_tokens WHERE token_hash = ?`, hash)
	var t InviteToken
	var used sql.NullTime
	err := row.Scan(&t.ID, &t.TokenHash, &t.UserID, &t.CreatedAt, &t.ExpiresAt, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.UsedAt = used.Time
	return &t, nil
}

// MarkInviteTokenUsed marks an invite token as consumed.
func (s *Store) MarkInviteTokenUsed(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE invite_tokens SET used_at = ? WHERE id = ?`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("store: mark invite token used: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateClient inserts an OIDC client.
func (s *Store) CreateClient(ctx context.Context, c *Client) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, scopes) VALUES (?, ?, ?, ?)`,
		c.ID, c.Secret, strings.Join(c.RedirectURIs, ","), strings.Join(c.Scopes, ","))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrDuplicateClient
		}
		return fmt.Errorf("store: create client: %w", err)
	}
	return nil
}

// ClientByID returns an OIDC client by ID.
func (s *Store) ClientByID(ctx context.Context, id string) (*Client, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, secret, redirect_uris, scopes, created_at FROM clients WHERE id = ?`, id)
	var c Client
	var redirects, scopes string
	err := row.Scan(&c.ID, &c.Secret, &redirects, &scopes, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.RedirectURIs = splitCSV(redirects)
	c.Scopes = splitCSV(scopes)
	return &c, nil
}

// ListClients returns all OIDC clients.
func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, secret, redirect_uris, scopes, created_at FROM clients ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: list clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Client
	for rows.Next() {
		var c Client
		var redirects, scopes string
		if err := rows.Scan(&c.ID, &c.Secret, &redirects, &scopes, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.RedirectURIs = splitCSV(redirects)
		c.Scopes = splitCSV(scopes)
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddWebAuthnCredential stores a passkey for a user.
func (s *Store) AddWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, data) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.SignCount, c.Data)
	if err != nil {
		return fmt.Errorf("store: add webauthn credential: %w", err)
	}
	return nil
}

// ListWebAuthnCredentials returns all passkeys for a user.
func (s *Store) ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, data, created_at FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list webauthn credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Data, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetWebAuthnCredential returns a passkey by credential ID.
func (s *Store) GetWebAuthnCredential(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, data, created_at FROM webauthn_credentials WHERE credential_id = ?`, credentialID)
	var c WebAuthnCredential
	err := row.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Data, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

// UpdateWebAuthnSignCount updates a passkey's sign count after a login.
func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, id string, signCount uint32) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`, signCount, id)
	if err != nil {
		return fmt.Errorf("store: update webauthn sign count: %w", err)
	}
	return nil
}

// AppendAudit writes an entry to the persistent audit log.
func (s *Store) AppendAudit(ctx context.Context, e *AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, tenant_id, actor, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		e.ID, e.TenantID, e.Actor, e.Action, e.Target, e.Detail)
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}

// ListAudit returns audit entries for a tenant, newest first.
func (s *Store) ListAudit(ctx context.Context, tenantID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, actor, action, target, detail, created_at FROM audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?`,
		tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TenantID, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// splitCSV splits a comma-joined column into a slice, dropping empties.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
