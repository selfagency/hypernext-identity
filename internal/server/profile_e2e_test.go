package server

import (
	"context"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/store"
)

// TestProfileHCardUsesStoreData proves the h-card renders the tenant's
// display name and bio from the store, not a host echo.
func TestProfileHCardUsesStoreData(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)
	ctx := context.Background()

	// Seed a published profile for the alice tenant.
	if err := ts.srv.store.UpsertProfilePage(ctx, &store.ProfilePage{
		ID:          "p1",
		TenantID:    "t1",
		AccountID:   "acct1",
		DisplayName: "Alice A.",
		Bio:         "I write Go.",
		IsPublished: true,
	}); err != nil {
		t.Fatal(err)
	}

	status, body := ts.get(t, "/profile/", "alice.example.com")
	if status != 200 {
		t.Fatalf("profile status = %d, want 200", status)
	}
	if !strings.Contains(body, `class="p-name">Alice A.`) {
		t.Fatalf("h-card missing display name from store: %s", body)
	}
	if !strings.Contains(body, "I write Go.") {
		t.Fatalf("h-card missing bio from store: %s", body)
	}
}

// TestProfileHCardUnpublished404 proves an unpublished profile is a uniform
// 404 (no tenant-enumeration signal).
func TestProfileHCardUnpublished404(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)
	ctx := context.Background()

	if err := ts.srv.store.UpsertProfilePage(ctx, &store.ProfilePage{
		ID:          "p1",
		TenantID:    "t1",
		AccountID:   "acct1",
		DisplayName: "Alice A.",
		IsPublished: false,
	}); err != nil {
		t.Fatal(err)
	}

	status, _ := ts.get(t, "/profile/", "alice.example.com")
	if status != 404 {
		t.Fatalf("unpublished profile status = %d, want 404", status)
	}
}

// TestProfileDIDDocFallback proves the DID doc falls back to did:web:<host>
// when the tenant has no explicit DID.
func TestProfileDIDDocFallback(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	status, body := ts.getWithAccept(t, "/profile/", "alice.example.com", "application/did+json")
	if status != 200 {
		t.Fatalf("DID doc status = %d, want 200", status)
	}
	if !strings.Contains(body, `"id":"did:web:alice.example.com"`) && !strings.Contains(body, `"id": "did:web:alice.example.com"`) {
		t.Fatalf("DID doc missing did:web fallback: %s", body)
	}
}
