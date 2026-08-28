package atproto

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/selfagency/sovereign/internal/storage"
)

// TestBlobStoreRoundTrip verifies blob put/get/delete.
func TestBlobStoreRoundTrip(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	bs := NewBlobStore(fs)
	ctx := context.Background()

	// Put
	key, err := bs.Put(ctx, bytes.NewReader([]byte("hello blob")))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if key == "" {
		t.Fatal("empty blob key")
	}

	// Get
	rc, err := bs.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	body, _ := io.ReadAll(rc)
	if string(body) != "hello blob" {
		t.Fatalf("got %q, want hello blob", body)
	}

	// Delete
	if err := bs.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := bs.Get(ctx, key); err == nil {
		t.Fatal("expected error after delete")
	}
}

// TestBlobStoreGetMissing verifies a missing blob errors.
func TestBlobStoreGetMissing(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	bs := NewBlobStore(fs)
	if _, err := bs.Get(context.Background(), "missing"); err == nil {
		t.Fatal("expected error for missing blob")
	}
}
