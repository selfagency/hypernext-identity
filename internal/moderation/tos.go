package moderation

import (
	"context"
	"errors"
	"net/http"
)

// ToSStore persists whether a tenant has accepted the Terms of Service.
type ToSStore interface {
	// Accepted reports whether the tenant has accepted the ToS.
	Accepted(ctx context.Context, tenantID string) (bool, error)
	// Accept records ToS acceptance.
	Accept(ctx context.Context, tenantID string) error
}

// MemoryToSStore is an in-memory ToS store (TDD-friendly).
type MemoryToSStore struct {
	accepted map[string]bool
}

// NewMemoryToSStore builds an empty ToS store.
func NewMemoryToSStore() *MemoryToSStore {
	return &MemoryToSStore{accepted: map[string]bool{}}
}

// Accepted reports whether the tenant accepted the ToS.
func (m *MemoryToSStore) Accepted(_ context.Context, tenantID string) (bool, error) {
	return m.accepted[tenantID], nil
}

// Accept records ToS acceptance.
func (m *MemoryToSStore) Accept(_ context.Context, tenantID string) error {
	m.accepted[tenantID] = true
	return nil
}

// ToSGate is middleware that blocks requests until the tenant accepts the ToS.
type ToSGate struct {
	Store ToSStore
}

// Middleware returns a handler that gates on ToS acceptance.
func (g *ToSGate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The ToS acceptance endpoint is always allowed.
		if r.URL.Path == "/admin/tos" {
			next.ServeHTTP(w, r)
			return
		}
		tenantID := r.FormValue("tenant")
		if tenantID == "" {
			// No tenant context; allow (the tenant middleware handles it).
			next.ServeHTTP(w, r)
			return
		}
		accepted, err := g.Store.Accepted(r.Context(), tenantID)
		if err != nil {
			http.Error(w, "tos store error", http.StatusInternalServerError)
			return
		}
		if !accepted {
			http.Error(w, "terms of service not accepted", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AcceptHandler serves the ToS acceptance endpoint.
type AcceptHandler struct {
	Store ToSStore
}

// ServeHTTP records ToS acceptance for a tenant.
func (h *AcceptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	tenantID := r.FormValue("tenant")
	if tenantID == "" {
		http.Error(w, "tenant is required", http.StatusBadRequest)
		return
	}
	if err := h.Store.Accept(r.Context(), tenantID); err != nil {
		http.Error(w, "tos store error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ErrNoToSStore is returned when no ToS store is configured.
var ErrNoToSStore = errors.New("no ToS store configured")
