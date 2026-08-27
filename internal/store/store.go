// Package store implements the SQLite persistence layer for the identity
// server's data models: public keys, profile pages/links, and proof claims.
// It uses modernc.org/sqlite (CGO-free) to keep the single-binary build.
package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Open opens (and creates if needed) a SQLite database at path and applies
// the schema migrations. It hardens the data directory and DB file
// permissions so the signing key and refresh-token hashes are not world-
// readable.
func Open(path string) (*Store, error) {
	// Ensure the parent directory is not group/world accessible.
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Enable foreign keys (OFF by default in SQLite) so ON DELETE CASCADE
	// works for profile_links.
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Restrict the DB file to owner-only (it holds the signing key).
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate applies the schema. Uses CREATE TABLE IF NOT EXISTS so it is
// idempotent across restarts.
func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS public_keys (
			id            TEXT PRIMARY KEY,
			tenant_id     TEXT NOT NULL,
			account_id    TEXT NOT NULL,
			key_type      TEXT NOT NULL,
			label         TEXT,
			fingerprint   TEXT NOT NULL,
			key_material  TEXT NOT NULL,
			algorithm     TEXT,
			revoked_at    TIMESTAMP,
			expires_at    TIMESTAMP,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, fingerprint)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_public_keys_account ON public_keys(account_id, key_type)`,
		`CREATE TABLE IF NOT EXISTS profile_pages (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL UNIQUE,
			account_id      TEXT NOT NULL,
			display_name    TEXT,
			bio             TEXT,
			avatar_blob_key TEXT,
			theme           TEXT NOT NULL DEFAULT 'default',
			is_published    BOOLEAN NOT NULL DEFAULT 0,
			sync_atproto_profile BOOLEAN NOT NULL DEFAULT 0,
			updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS profile_links (
			id              TEXT PRIMARY KEY,
			profile_page_id TEXT NOT NULL REFERENCES profile_pages(id) ON DELETE CASCADE,
			position        INTEGER NOT NULL,
			kind            TEXT NOT NULL,
			brand_key       TEXT,
			label           TEXT NOT NULL,
			url             TEXT NOT NULL,
			icon_blob_key   TEXT,
			is_visible      BOOLEAN NOT NULL DEFAULT 1,
			click_count     INTEGER NOT NULL DEFAULT 0,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_profile_links_page_position ON profile_links(profile_page_id, position)`,
		`CREATE TABLE IF NOT EXISTS proof_claims (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL,
			account_id      TEXT NOT NULL,
			anchor_type     TEXT NOT NULL,
			anchor_value    TEXT NOT NULL,
			service         TEXT NOT NULL,
			claim_location  TEXT NOT NULL,
			expected_token  TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT 'pending',
			last_checked_at TIMESTAMP,
			last_error      TEXT,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, service, claim_location)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_proof_claims_recheck ON proof_claims(status, last_checked_at)`,
		`CREATE TABLE IF NOT EXISTS auth_signing_keys (
			id         TEXT PRIMARY KEY,
			key_pem    TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
			token      TEXT PRIMARY KEY,
			subject    TEXT NOT NULL,
			client_id  TEXT NOT NULL,
			scopes     TEXT NOT NULL,
			auth_time  TIMESTAMP NOT NULL,
			expires_at TIMESTAMP,
			revoked_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// NOTE: existing databases created before the expires_at/revoked_at
		// columns are upgraded by the migration runner (PR2). Fresh databases
		// get the columns from the CREATE TABLE above.
		`CREATE TABLE IF NOT EXISTS tenants (
			id         TEXT PRIMARY KEY,
			handle     TEXT NOT NULL UNIQUE,
			did_method TEXT NOT NULL DEFAULT 'web',
			did        TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// isUniqueViolation reports whether a SQLite error is a UNIQUE constraint
// violation (SQLITE_CONSTRAINT_UNIQUE, code 2067).
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// nullableTime converts a zero time.Time to a NULL for SQLite columns.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
