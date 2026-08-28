package moderation

import (
	"context"
	"time"

	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// StoreAuditLog is a SQLite-backed AuditLog that persists entries across
// restarts. It replaces the in-memory MemoryAuditLog for production use.
type StoreAuditLog struct {
	store *store.Store
}

// NewStoreAuditLog builds a persistent audit log over the store.
func NewStoreAuditLog(st *store.Store) *StoreAuditLog {
	return &StoreAuditLog{store: st}
}

// Append records an audit entry. The tenant is taken from the request
// context (set by the tenant middleware), never from the entry.
func (s *StoreAuditLog) Append(ctx context.Context, e AuditEntry) error {
	tenantID := ""
	if t, ok := tenant.FromContext(ctx); ok {
		tenantID = t.ID
	}
	return s.store.AppendAudit(ctx, &store.AuditEntry{
		ID:        e.Resource + "-" + e.Action + "-" + e.Timestamp.Format(time.RFC3339Nano),
		TenantID:  tenantID,
		Actor:     e.Action,
		Action:    e.Action,
		Target:    e.Resource,
		Detail:    e.Reason,
		CreatedAt: e.Timestamp,
	})
}

// List returns the most recent entries for the tenant in context.
func (s *StoreAuditLog) List(ctx context.Context, limit int) ([]AuditEntry, error) {
	tenantID := ""
	if t, ok := tenant.FromContext(ctx); ok {
		tenantID = t.ID
	}
	entries, err := s.store.ListAudit(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]AuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, AuditEntry{
			Timestamp: e.CreatedAt,
			Action:    e.Action,
			Resource:  e.Target,
			Reason:    e.Detail,
		})
	}
	return out, nil
}
