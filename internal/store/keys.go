package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// PublicKey is a stored public key row.
type PublicKey struct {
	ID          string
	TenantID    string
	AccountID   string
	KeyType     string // "ssh" | "pgp"
	Label       string
	Fingerprint string
	KeyMaterial string
	Algorithm   string
	RevokedAt   *time.Time
	ExpiresAt   *time.Time
	CreatedAt   time.Time
}

// ErrDuplicateFingerprint is returned when a tenant already has a key with
// the same fingerprint.
var ErrDuplicateFingerprint = errors.New("store: duplicate fingerprint")

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// CreatePublicKey inserts a public key, rejecting duplicate fingerprints.
func (s *Store) CreatePublicKey(ctx context.Context, k *PublicKey) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO public_keys (id, tenant_id, account_id, key_type, label, fingerprint, key_material, algorithm, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.TenantID, k.AccountID, k.KeyType, k.Label, k.Fingerprint, k.KeyMaterial, k.Algorithm, k.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateFingerprint
		}
		return err
	}
	return nil
}

// ListPublicKeys returns a tenant's keys, optionally filtered by type.
func (s *Store) ListPublicKeys(ctx context.Context, tenantID, keyType string) ([]PublicKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, account_id, key_type, label, fingerprint, key_material, algorithm, revoked_at, expires_at, created_at
		 FROM public_keys WHERE tenant_id = ? AND (? = '' OR key_type = ?) ORDER BY created_at`,
		tenantID, keyType, keyType)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanPublicKeys(rows)
}

// GetPublicKey returns a single key by ID, scoped to the tenant.
func (s *Store) GetPublicKey(ctx context.Context, tenantID, id string) (*PublicKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, account_id, key_type, label, fingerprint, key_material, algorithm, revoked_at, expires_at, created_at
		 FROM public_keys WHERE tenant_id = ? AND id = ?`, tenantID, id)
	k, err := scanPublicKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}

// RevokePublicKey marks a key revoked (scoped to tenant + account).
func (s *Store) RevokePublicKey(ctx context.Context, tenantID, accountID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE public_keys SET revoked_at = ? WHERE tenant_id = ? AND account_id = ? AND id = ?`,
		time.Now().UTC(), tenantID, accountID, id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

// DeletePublicKey removes a key (scoped to tenant + account).
func (s *Store) DeletePublicKey(ctx context.Context, tenantID, accountID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM public_keys WHERE tenant_id = ? AND account_id = ? AND id = ?`,
		tenantID, accountID, id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func scanPublicKeys(rows *sql.Rows) ([]PublicKey, error) {
	var out []PublicKey
	for rows.Next() {
		var k PublicKey
		if err := rows.Scan(&k.ID, &k.TenantID, &k.AccountID, &k.KeyType, &k.Label,
			&k.Fingerprint, &k.KeyMaterial, &k.Algorithm, &k.RevokedAt, &k.ExpiresAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func scanPublicKey(row *sql.Row) (*PublicKey, error) {
	var k PublicKey
	err := row.Scan(&k.ID, &k.TenantID, &k.AccountID, &k.KeyType, &k.Label,
		&k.Fingerprint, &k.KeyMaterial, &k.Algorithm, &k.RevokedAt, &k.ExpiresAt, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
