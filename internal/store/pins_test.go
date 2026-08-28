package store

import (
	"context"
	"errors"
	"testing"
)

// TestIPFSPinCRUD verifies AddIPFSPin is idempotent and GetIPFSPin returns
// the record or ErrNotFound.
func TestIPFSPinCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	cid := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

	// Add then get.
	if err := s.AddIPFSPin(ctx, cid, "pinned"); err != nil {
		t.Fatalf("AddIPFSPin: %v", err)
	}
	p, err := s.GetIPFSPin(ctx, cid)
	if err != nil {
		t.Fatalf("GetIPFSPin: %v", err)
	}
	if p.CID != cid || p.Status != "pinned" {
		t.Fatalf("GetIPFSPin = %+v, want cid=%s status=pinned", p, cid)
	}

	// Idempotent re-add updates status.
	if err := s.AddIPFSPin(ctx, cid, "pinning"); err != nil {
		t.Fatalf("AddIPFSPin (update): %v", err)
	}
	p, _ = s.GetIPFSPin(ctx, cid)
	if p.Status != "pinning" {
		t.Fatalf("status after re-add = %q, want pinning", p.Status)
	}
}

// TestGetIPFSPinMissing verifies a missing CID returns ErrNotFound.
func TestGetIPFSPinMissing(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetIPFSPin(context.Background(), "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}
