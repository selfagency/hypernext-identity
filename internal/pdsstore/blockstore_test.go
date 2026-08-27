package pdsstore

import (
	"context"
	"path/filepath"
	"testing"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
)

// newTestBlockstore opens a temp SQLite blockstore.
func newTestBlockstore(t *testing.T) *Blockstore {
	t.Helper()
	b, err := Open(filepath.Join(t.TempDir(), "blocks.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// TestPutGet verifies a block round-trips.
func TestPutGet(t *testing.T) {
	b := newTestBlockstore(t)
	ctx := context.Background()

	block := blocks.NewBlock([]byte("hello repo"))
	if err := b.Put(ctx, block); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := b.Get(ctx, block.Cid())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.RawData()) != "hello repo" {
		t.Fatalf("data = %q, want hello repo", got.RawData())
	}
}

// TestGetMissing verifies a missing block returns ErrNotFound.
func TestGetMissing(t *testing.T) {
	b := newTestBlockstore(t)
	ctx := context.Background()
	c := cid.NewCidV1(cid.Raw, []byte("missing"))
	if _, err := b.Get(ctx, c); err == nil {
		t.Fatal("expected error for missing block")
	} else if _, ok := err.(*ipld.ErrNotFound); !ok {
		t.Fatalf("error = %T, want *ipld.ErrNotFound", err)
	}
}

// TestHas verifies Has reports presence.
func TestHas(t *testing.T) {
	b := newTestBlockstore(t)
	ctx := context.Background()
	block := blocks.NewBlock([]byte("x"))
	_ = b.Put(ctx, block)

	ok, err := b.Has(ctx, block.Cid())
	if err != nil || !ok {
		t.Fatalf("Has = %v, %v, want true", ok, err)
	}
	missing := cid.NewCidV1(cid.Raw, []byte("nope"))
	ok, _ = b.Has(ctx, missing)
	if ok {
		t.Fatal("Has should be false for missing block")
	}
}

// TestGetSize verifies GetSize returns the block size.
func TestGetSize(t *testing.T) {
	b := newTestBlockstore(t)
	ctx := context.Background()
	block := blocks.NewBlock([]byte("12345"))
	_ = b.Put(ctx, block)

	size, err := b.GetSize(ctx, block.Cid())
	if err != nil || size != 5 {
		t.Fatalf("GetSize = %d, %v, want 5", size, err)
	}
}

// TestPutMany verifies batched puts.
func TestPutMany(t *testing.T) {
	b := newTestBlockstore(t)
	ctx := context.Background()
	bs := []blocks.Block{blocks.NewBlock([]byte("a")), blocks.NewBlock([]byte("b"))}
	if err := b.PutMany(ctx, bs); err != nil {
		t.Fatalf("PutMany: %v", err)
	}
	for _, block := range bs {
		ok, _ := b.Has(ctx, block.Cid())
		if !ok {
			t.Fatalf("block %s missing after PutMany", block.Cid())
		}
	}
}

// TestDeleteBlock removes a block.
func TestDeleteBlock(t *testing.T) {
	b := newTestBlockstore(t)
	ctx := context.Background()
	block := blocks.NewBlock([]byte("x"))
	_ = b.Put(ctx, block)
	if err := b.DeleteBlock(ctx, block.Cid()); err != nil {
		t.Fatalf("DeleteBlock: %v", err)
	}
	ok, _ := b.Has(ctx, block.Cid())
	if ok {
		t.Fatal("block should be deleted")
	}
}

// TestAllKeysChan verifies AllKeysChan returns all CIDs.
func TestAllKeysChan(t *testing.T) {
	b := newTestBlockstore(t)
	ctx := context.Background()
	bs := []blocks.Block{blocks.NewBlock([]byte("a")), blocks.NewBlock([]byte("b"))}
	_ = b.PutMany(ctx, bs)

	ch, err := b.AllKeysChan(ctx)
	if err != nil {
		t.Fatalf("AllKeysChan: %v", err)
	}
	count := 0
	for range ch {
		count++
	}
	if count != 2 {
		t.Fatalf("AllKeysChan = %d, want 2", count)
	}
}

// TestPersistenceAcrossReopen verifies blocks survive a reopen (the whole
// point of durable storage).
func TestPersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocks.db")
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	block := blocks.NewBlock([]byte("persistent"))
	if err := b.Put(context.Background(), block); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()

	// Reopen and verify the block is still there.
	b2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b2.Close() }()
	got, err := b2.Get(context.Background(), block.Cid())
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if string(got.RawData()) != "persistent" {
		t.Fatalf("data = %q, want persistent", got.RawData())
	}
}
