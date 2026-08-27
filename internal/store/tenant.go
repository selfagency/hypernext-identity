package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Tenant is a stored tenant row.
type Tenant struct {
	ID        string
	Handle    string
	DIDMethod string
	DID       string
	CreatedAt time.Time
}

// CreateTenant inserts a tenant, rejecting duplicate handles.
func (s *Store) CreateTenant(ctx context.Context, t *Tenant) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (id, handle, did_method, did, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Handle, t.DIDMethod, t.DID, t.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateTenant
		}
		return err
	}
	return nil
}

// ErrDuplicateTenant is returned when a tenant handle already exists.
var ErrDuplicateTenant = errors.New("store: duplicate tenant")

// GetTenantByHandle returns a tenant by handle.
func (s *Store) GetTenantByHandle(ctx context.Context, handle string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, handle, did_method, did, created_at FROM tenants WHERE handle = ?`, handle)
	var t Tenant
	err := row.Scan(&t.ID, &t.Handle, &t.DIDMethod, &t.DID, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &t, err
}

// ListTenants returns all tenants.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, handle, did_method, did, created_at FROM tenants ORDER BY handle`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Handle, &t.DIDMethod, &t.DID, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTenant removes a tenant by handle.
func (s *Store) DeleteTenant(ctx context.Context, handle string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE handle = ?`, handle)
	if err != nil {
		return err
	}
	return requireAffected(res)
}
