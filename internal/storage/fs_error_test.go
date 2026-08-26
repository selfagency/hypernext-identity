package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestFSPutError verifies Put returns an error when the target dir can't be created.
func TestFSPutError(t *testing.T) {
	// Root is a file, so MkdirAll under it fails.
	root := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &FS{Root: root}
	if _, err := f.Put(context.Background(), "a/b.txt", bytes.NewReader([]byte("x")), "text/plain"); err == nil {
		t.Fatal("expected error when parent is a file")
	}
}

// TestFSGetError verifies Get returns ErrNotFound for missing keys.
func TestFSGetError(t *testing.T) {
	f := &FS{Root: t.TempDir()}
	if _, _, err := f.Get(context.Background(), "missing.txt"); err != ErrNotFound {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

// TestFSDeleteError verifies Delete returns ErrNotFound for missing keys.
func TestFSDeleteError(t *testing.T) {
	f := &FS{Root: t.TempDir()}
	if err := f.Delete(context.Background(), "missing.txt"); err != ErrNotFound {
		t.Fatalf("Delete missing = %v, want ErrNotFound", err)
	}
}

// TestFSListEmpty verifies List on a non-existent prefix returns empty.
func TestFSListEmpty(t *testing.T) {
	f := &FS{Root: t.TempDir()}
	blobs, err := f.List(context.Background(), "nope/")
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 0 {
		t.Fatalf("list = %d items, want 0", len(blobs))
	}
}

// TestFSPathTraversal verifies keys escaping Root are rejected.
func TestFSPathTraversal(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	// A key with ../ should be contained within Root.
	if _, err := f.Put(context.Background(), "../../escape.txt", bytes.NewReader([]byte("x")), "text/plain"); err != nil {
		t.Fatal(err)
	}
	// The file must NOT exist outside Root.
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); err == nil {
		t.Fatal("path traversal escaped root")
	}
}
