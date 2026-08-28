package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// IPFSPin is a persisted IPFS pin record.
type IPFSPin struct {
	CID       string
	Status    string
	CreatedAt time.Time
}

// AddIPFSPin records a pinned CID (idempotent).
func (s *Store) AddIPFSPin(ctx context.Context, cid, status string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ipfs_pins (cid, status) VALUES (?, ?)
		 ON CONFLICT(cid) DO UPDATE SET status = excluded.status`,
		cid, status)
	if err != nil {
		return fmt.Errorf("store: add ipfs pin: %w", err)
	}
	return nil
}

// GetIPFSPin returns a pin by CID, or ErrNotFound.
func (s *Store) GetIPFSPin(ctx context.Context, cid string) (*IPFSPin, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT cid, status, created_at FROM ipfs_pins WHERE cid = ?`, cid)
	var p IPFSPin
	err := row.Scan(&p.CID, &p.Status, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}
