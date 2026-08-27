package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Account is a stored account row. It holds the identity primitives (DID,
// WebID) that authorization and profile features depend on. Web3/SIWE/ENS
// identity is deliberately out of scope.
type Account struct {
	ID        string
	TenantID  string
	DID       string
	WebID     string
	CreatedAt time.Time
}

// CreateAccount inserts an account, rejecting duplicate (tenant_id, did).
func (s *Store) CreateAccount(ctx context.Context, a *Account) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO accounts (id, tenant_id, did, webid, created_at) VALUES (?, ?, ?, ?, ?)`,
		a.ID, a.TenantID, a.DID, a.WebID, a.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateAccount
		}
		return err
	}
	return nil
}

// ErrDuplicateAccount is returned when an account already exists for a
// (tenant_id, did) pair.
var ErrDuplicateAccount = errors.New("store: duplicate account")

// AccountByWebID returns the account whose WebID matches, or ErrNotFound.
func (s *Store) AccountByWebID(ctx context.Context, webID string) (*Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, did, webid, created_at FROM accounts WHERE webid = ?`, webID)
	var a Account
	err := row.Scan(&a.ID, &a.TenantID, &a.DID, &a.WebID, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &a, err
}
