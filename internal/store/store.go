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
// readable. Pragmas (foreign keys, WAL, busy timeout) are set via the DSN so
// they apply to every pooled connection.
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
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows a single writer at a time; cap the pool to one open
	// connection so concurrent writes serialize instead of contending on
	// the database lock. Idle connections and connection lifetime bound the
	// pool so stale handles are recycled.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
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

// DB exposes the underlying database handle for tests and advanced callers.
func (s *Store) DB() *sql.DB {
	return s.db
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

// nullableString converts an empty string to a NULL for SQLite columns.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
