package moderation

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// TestStoreAuditLogPersists verifies audit entries survive a store reopen.
func TestStoreAuditLogPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.CreateTenant(ctx, &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	ctx = tenant.WithTenant(ctx, &tenant.Tenant{ID: "t1", Handle: "alice.example.com"})

	log := NewStoreAuditLog(st)
	if err := log.Append(ctx, AuditEntry{Timestamp: time.Now().UTC(), Action: "takedown", Resource: "docs/secret", Reason: "spam"}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	// Reopen and verify the entry persisted.
	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	log2 := NewStoreAuditLog(st2)
	entries, err := log2.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Resource != "docs/secret" || entries[0].Action != "takedown" {
		t.Fatalf("entry = %+v", entries[0])
	}
}
