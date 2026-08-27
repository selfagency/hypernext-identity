package storage

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
)

// TestPrefixedIsolation verifies the Prefixed backend namespaces keys so two
// prefixes cannot read each other's data.
func TestPrefixedIsolation(t *testing.T) {
	root := t.TempDir()
	base := &FS{Root: root}
	alice := &Prefixed{Backend: base, Prefix: "alice"}
	bob := &Prefixed{Backend: base, Prefix: "bob"}

	ctx := context.Background()
	if _, err := alice.Put(ctx, "docs/x", bytes.NewReader([]byte("alice data")), "text/plain"); err != nil {
		t.Fatalf("alice put: %v", err)
	}

	// Alice can read her own blob.
	rc, _, err := alice.Get(ctx, "docs/x")
	if err != nil {
		t.Fatalf("alice get: %v", err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "alice data" {
		t.Fatalf("alice body = %q", b)
	}

	// Bob cannot read Alice's blob (different prefix -> not found).
	if _, _, err := bob.Get(ctx, "docs/x"); err != ErrNotFound {
		t.Fatalf("bob get = %v, want ErrNotFound", err)
	}
}

// TestPrefixedList verifies List is scoped to the prefix.
func TestPrefixedList(t *testing.T) {
	root := t.TempDir()
	base := &FS{Root: root}
	alice := &Prefixed{Backend: base, Prefix: "alice"}
	bob := &Prefixed{Backend: base, Prefix: "bob"}

	ctx := context.Background()
	_, _ = alice.Put(ctx, "docs/a", bytes.NewReader([]byte("a")), "text/plain")
	_, _ = bob.Put(ctx, "docs/b", bytes.NewReader([]byte("b")), "text/plain")

	// Alice lists only her own blobs.
	blobs, err := alice.List(ctx, "docs")
	if err != nil {
		t.Fatalf("alice list: %v", err)
	}
	if len(blobs) != 1 || blobs[0].Key != "alice/docs/a" {
		t.Fatalf("alice blobs = %+v, want [alice/docs/a]", blobs)
	}
}

// TestPrefixedDelete verifies Delete removes the prefixed key.
func TestPrefixedDelete(t *testing.T) {
	root := t.TempDir()
	base := &FS{Root: root}
	alice := &Prefixed{Backend: base, Prefix: "alice"}

	ctx := context.Background()
	_, _ = alice.Put(ctx, "docs/x", bytes.NewReader([]byte("x")), "text/plain")
	if err := alice.Delete(ctx, "docs/x"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := alice.Get(ctx, "docs/x"); err != ErrNotFound {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

// TestPrefixedPath verifies the prefixed key is a subdirectory on FS.
func TestPrefixedPath(t *testing.T) {
	root := t.TempDir()
	base := &FS{Root: root}
	alice := &Prefixed{Backend: base, Prefix: "alice"}

	ctx := context.Background()
	_, _ = alice.Put(ctx, "docs/x", bytes.NewReader([]byte("x")), "text/plain")

	// The blob lives under root/alice/docs/x.
	if _, err := filepath.Glob(filepath.Join(root, "alice", "docs", "x")); err != nil {
		t.Fatalf("glob: %v", err)
	}
	if _, _, err := (&FS{Root: root}).Get(ctx, "alice/docs/x"); err != nil {
		t.Fatalf("raw get of prefixed key: %v", err)
	}
}

// TestPrefixedRejectsTraversal verifies the Prefixed backend rejects keys
// that would escape the tenant namespace. path.Join silently cleans
// traversal ("a" + "/../b/x" -> "b/x"), which would let a tenant read or
// write another tenant's blobs. The hardened key() must reject these.
func TestPrefixedRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	base := &FS{Root: root}
	alice := &Prefixed{Backend: base, Prefix: "alice"}
	ctx := context.Background()

	// Seed a blob under bob's namespace directly.
	if _, err := base.Put(ctx, "bob/docs/secret", bytes.NewReader([]byte("bob secret")), "text/plain"); err != nil {
		t.Fatalf("seed bob blob: %v", err)
	}

	// Every traversal/absolute key must be rejected, not silently cleaned.
	badKeys := []string{
		"/../bob/docs/secret",
		"../bob/docs/secret",
		"../../bob/docs/secret",
		"docs/../../bob/docs/secret",
		"/bob/docs/secret",
		"..",
		"../",
		"",
	}
	for _, k := range badKeys {
		if _, _, err := alice.Get(ctx, k); err == nil {
			t.Fatalf("Get(%q) succeeded — traversal not rejected", k)
		}
		if _, err := alice.Put(ctx, k, bytes.NewReader([]byte("x")), "text/plain"); err == nil {
			t.Fatalf("Put(%q) succeeded — traversal not rejected", k)
		}
	}

	// Alice must not be able to read bob's blob via any crafted key.
	if _, _, err := alice.Get(ctx, "../bob/docs/secret"); err == nil {
		t.Fatal("alice read bob's blob via traversal")
	}
}
