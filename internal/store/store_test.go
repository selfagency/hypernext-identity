package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore opens an in-memory SQLite store.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestPublicKeyCRUD verifies create/list/get/revoke/delete.
func TestPublicKeyCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	k := PublicKey{
		ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "ssh",
		Fingerprint: "fp1", KeyMaterial: "ssh-ed25519 AAAA", Algorithm: "ssh-ed25519",
	}
	if err := s.CreatePublicKey(ctx, &k); err != nil {
		t.Fatalf("CreatePublicKey: %v", err)
	}

	// Duplicate fingerprint rejected.
	if err := s.CreatePublicKey(ctx, &k); !errors.Is(err, ErrDuplicateFingerprint) {
		t.Fatalf("duplicate = %v, want ErrDuplicateFingerprint", err)
	}

	// List.
	keys, err := s.ListPublicKeys(ctx, "t1", "")
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListPublicKeys = %d, %v", len(keys), err)
	}

	// Get.
	got, err := s.GetPublicKey(ctx, "t1", "k1")
	if err != nil || got.Fingerprint != "fp1" {
		t.Fatalf("GetPublicKey = %+v, %v", got, err)
	}

	// Revoke.
	if err := s.RevokePublicKey(ctx, "t1", "a1", "k1"); err != nil {
		t.Fatalf("RevokePublicKey: %v", err)
	}
	got, _ = s.GetPublicKey(ctx, "t1", "k1")
	if got.RevokedAt == nil {
		t.Fatal("key should be revoked")
	}

	// Delete.
	if err := s.DeletePublicKey(ctx, "t1", "a1", "k1"); err != nil {
		t.Fatalf("DeletePublicKey: %v", err)
	}
	if _, err := s.GetPublicKey(ctx, "t1", "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

// TestPublicKeyOwnership verifies cross-account operations are rejected.
func TestPublicKeyOwnership(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePublicKey(ctx, &PublicKey{ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "x"})

	// Wrong account cannot revoke.
	if err := s.RevokePublicKey(ctx, "t1", "a2", "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-account revoke = %v, want ErrNotFound", err)
	}
	// Wrong tenant cannot get.
	if _, err := s.GetPublicKey(ctx, "t2", "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get = %v, want ErrNotFound", err)
	}
}

// TestProfilePageUpsert verifies upsert + get.
func TestProfilePageUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	p := ProfilePage{ID: "p1", TenantID: "t1", AccountID: "a1", DisplayName: "Alice", Theme: "default", IsPublished: true, UpdatedAt: time.Now()}
	if err := s.UpsertProfilePage(ctx, &p); err != nil {
		t.Fatalf("UpsertProfilePage: %v", err)
	}

	// Upsert updates.
	p.DisplayName = "Alice Updated"
	if err := s.UpsertProfilePage(ctx, &p); err != nil {
		t.Fatalf("UpsertProfilePage: %v", err)
	}
	got, err := s.GetProfilePage(ctx, "t1")
	if err != nil || got.DisplayName != "Alice Updated" {
		t.Fatalf("GetProfilePage = %+v, %v", got, err)
	}
}

// TestProfileLinks verifies add/list/reorder/delete + cascade.
func TestProfileLinks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &ProfilePage{ID: "p1", TenantID: "t1", AccountID: "a1", UpdatedAt: time.Now()})

	_ = s.AddProfileLink(ctx, &ProfileLink{ID: "l1", ProfilePageID: "p1", Position: 0, Kind: "custom", Label: "Site", URL: "https://example.com", CreatedAt: time.Now()})
	_ = s.AddProfileLink(ctx, &ProfileLink{ID: "l2", ProfilePageID: "p1", Position: 1, Kind: "custom", Label: "Blog", URL: "https://blog.example.com", CreatedAt: time.Now()})

	links, err := s.ListProfileLinks(ctx, "p1")
	if err != nil || len(links) != 2 {
		t.Fatalf("ListProfileLinks = %d, %v", len(links), err)
	}

	// Reorder atomically.
	if err := s.ReorderProfileLinks(ctx, "p1", []string{"l2", "l1"}); err != nil {
		t.Fatalf("ReorderProfileLinks: %v", err)
	}
	links, _ = s.ListProfileLinks(ctx, "p1")
	if links[0].ID != "l2" {
		t.Fatalf("reorder failed: first = %s", links[0].ID)
	}

	// Delete page cascades to links.
	if err := s.DeleteProfilePage(ctx, "t1"); err != nil {
		t.Fatalf("DeleteProfilePage: %v", err)
	}
	links, _ = s.ListProfileLinks(ctx, "p1")
	if len(links) != 0 {
		t.Fatalf("cascade delete left %d links", len(links))
	}
}

// TestProofClaimCRUD verifies claim create/list/update/delete.
func TestProofClaimCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	c := ProofClaim{
		ID: "c1", TenantID: "t1", AccountID: "a1", AnchorType: "did", AnchorValue: "did:plc:x",
		Service: "dns", ClaimLocation: "_atproto.example.com", ExpectedToken: "did:plc:x", Status: "pending", CreatedAt: time.Now(),
	}
	if err := s.CreateProofClaim(ctx, &c); err != nil {
		t.Fatalf("CreateProofClaim: %v", err)
	}

	// Duplicate rejected.
	if err := s.CreateProofClaim(ctx, &c); !errors.Is(err, ErrDuplicateClaim) {
		t.Fatalf("duplicate = %v, want ErrDuplicateClaim", err)
	}

	// Update status.
	if err := s.UpdateProofClaimStatus(ctx, "t1", "c1", "verified", ""); err != nil {
		t.Fatalf("UpdateProofClaimStatus: %v", err)
	}

	// Verified list.
	verified, err := s.VerifiedProofClaims(ctx, "t1")
	if err != nil || len(verified) != 1 || verified[0].Status != "verified" {
		t.Fatalf("VerifiedProofClaims = %d, %v", len(verified), err)
	}

	// Delete.
	if err := s.DeleteProofClaim(ctx, "t1", "a1", "c1"); err != nil {
		t.Fatalf("DeleteProofClaim: %v", err)
	}
	claims, _ := s.ListProofClaims(ctx, "t1")
	if len(claims) != 0 {
		t.Fatalf("after delete = %d claims", len(claims))
	}
}
