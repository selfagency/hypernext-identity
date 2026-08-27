// Package moderation implements the minimum moderation surface: a takedown
// endpoint that removes a resource and records an audit entry, plus a
// first-run Terms-of-Service gate.
package moderation

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/hypernext/identity/internal/storage"
	"github.com/hypernext/identity/internal/tenant"
)

// AuditEntry records a moderation action.
type AuditEntry struct {
	// Timestamp is when the action occurred.
	Timestamp time.Time
	// Action is "takedown" or "restore".
	Action string
	// Resource is the taken-down resource key.
	Resource string
	// Reason is the moderation reason.
	Reason string
}

// AuditLog persists moderation audit entries.
type AuditLog interface {
	// Append records an audit entry.
	Append(ctx context.Context, e AuditEntry) error
	// List returns recent audit entries.
	List(ctx context.Context, limit int) ([]AuditEntry, error)
}

// MemoryAuditLog is an in-memory audit log (TDD-friendly; a SQLite-backed
// store replaces it in a later phase).
type MemoryAuditLog struct {
	entries []AuditEntry
}

// Append records an audit entry.
func (m *MemoryAuditLog) Append(_ context.Context, e AuditEntry) error {
	m.entries = append(m.entries, e)
	return nil
}

// List returns the most recent entries.
func (m *MemoryAuditLog) List(_ context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > len(m.entries) {
		limit = len(m.entries)
	}
	out := make([]AuditEntry, limit)
	copy(out, m.entries[len(m.entries)-limit:])
	return out, nil
}

// TakedownHandler serves the moderation takedown endpoint.
type TakedownHandler struct {
	// Backend returns the storage backend for a tenant.
	Backend func(tenantID string) storage.Backend
	// Log records audit entries.
	Log AuditLog
	// AdminAuthorizer reports whether the request principal is an admin.
	AdminAuthorizer func(r *http.Request) bool
}

// ServeHTTP handles takedown requests: POST /moderation/takedown with
// {resource, reason}. The tenant is derived from the authenticated request
// context (set by the tenant middleware), never from form input, and the
// caller must be an admin.
func (h *TakedownHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.AdminAuthorizer != nil && !h.AdminAuthorizer(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	resource := r.FormValue("resource")
	reason := r.FormValue("reason")
	if resource == "" {
		http.Error(w, "resource is required", http.StatusBadRequest)
		return
	}
	if reason == "" {
		http.Error(w, "reason is required", http.StatusBadRequest)
		return
	}

	// Takedown: delete the resource from the tenant's backend. The tenant is
	// taken from the request context, not the form (S11).
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "tenant context required", http.StatusBadRequest)
		return
	}
	backend := h.Backend(t.ID)
	if err := backend.Delete(r.Context(), resource); err != nil {
		http.Error(w, "resource not found", http.StatusNotFound)
		return
	}

	if err := h.Log.Append(r.Context(), AuditEntry{
		Timestamp: time.Now().UTC(),
		Action:    "takedown",
		Resource:  resource,
		Reason:    reason,
	}); err != nil {
		http.Error(w, "audit log error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ErrNoAuditLog is returned when no audit log is configured.
var ErrNoAuditLog = errors.New("no audit log configured")
