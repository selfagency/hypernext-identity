package storage

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// RunContractTests exercises any Backend implementation identically.
// Each backend's test file calls this with its own constructor, so the
// same suite runs against fs and s3 with zero drift.
func RunContractTests(t *testing.T, newBackend func() Backend) {
	t.Helper()

	t.Run("put then get returns same bytes", func(t *testing.T) {
		b := newBackend()
		ctx := context.Background()
		want := []byte("hello world")
		if _, err := b.Put(ctx, "a/b.txt", bytes.NewReader(want), "text/plain"); err != nil {
			t.Fatal(err)
		}
		rc, blob, err := b.Get(ctx, "a/b.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		if blob.ContentType != "text/plain" {
			t.Fatalf("content type = %q, want text/plain", blob.ContentType)
		}
		got := new(bytes.Buffer)
		if _, err := io.Copy(got, rc); err != nil {
			t.Fatal(err)
		}
		if got.String() != string(want) {
			t.Fatalf("got %q want %q", got.String(), want)
		}
	})

	t.Run("delete removes key", func(t *testing.T) {
		b := newBackend()
		ctx := context.Background()
		if _, err := b.Put(ctx, "gone.txt", bytes.NewReader([]byte("x")), "text/plain"); err != nil {
			t.Fatal(err)
		}
		if err := b.Delete(ctx, "gone.txt"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := b.Get(ctx, "gone.txt"); err == nil {
			t.Fatal("expected error after delete")
		}
	})

	t.Run("delete missing key is idempotent or ErrNotFound", func(t *testing.T) {
		b := newBackend()
		// FS returns ErrNotFound for a missing delete; S3 is idempotent
		// (returns nil). Both are valid — the contract is that a missing
		// delete does not error fatally.
		err := b.Delete(context.Background(), "never-existed.txt")
		if err != nil && err != ErrNotFound {
			t.Fatalf("delete missing = %v, want nil or ErrNotFound", err)
		}
	})

	t.Run("get missing key returns error", func(t *testing.T) {
		b := newBackend()
		if _, _, err := b.Get(context.Background(), "nope.txt"); err == nil {
			t.Fatal("expected error for missing key")
		}
	})

	t.Run("list returns keys under prefix", func(t *testing.T) {
		b := newBackend()
		ctx := context.Background()
		for _, k := range []string{"dir/a.txt", "dir/b.txt", "other/c.txt"} {
			if _, err := b.Put(ctx, k, bytes.NewReader([]byte("x")), "text/plain"); err != nil {
				t.Fatal(err)
			}
		}
		got, err := b.List(ctx, "dir/")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("list dir/ = %d items, want 2", len(got))
		}
	})

	t.Run("overwrite replaces content", func(t *testing.T) {
		b := newBackend()
		ctx := context.Background()
		if _, err := b.Put(ctx, "k", bytes.NewReader([]byte("v1")), "text/plain"); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Put(ctx, "k", bytes.NewReader([]byte("v2")), "text/plain"); err != nil {
			t.Fatal(err)
		}
		rc, _, err := b.Get(ctx, "k")
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		got := new(bytes.Buffer)
		io.Copy(got, rc)
		if got.String() != "v2" {
			t.Fatalf("got %q want v2", got.String())
		}
	})
}
