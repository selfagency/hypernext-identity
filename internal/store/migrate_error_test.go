package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrateV5ErrorPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	// Canceled context makes the first QueryContext fail.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := migrateV5(ctx, tx); err == nil {
		t.Fatal("expected migrateV5 error on canceled context")
	}
}

func TestMigrateV6ErrorPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := migrateV6(ctx, tx); err == nil {
		t.Fatal("expected migrateV6 error on canceled context")
	}
}
