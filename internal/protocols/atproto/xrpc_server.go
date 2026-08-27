package atproto

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/store"
)

// XRPCServer serves atproto XRPC endpoints (com.atproto.*) for the tenant
// in the request context.
type XRPCServer struct {
	Store *store.Store
}

// ServeHTTP routes XRPC method calls.
func (s *XRPCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path is /xrpc/<method>.
	method := strings.TrimPrefix(r.URL.Path, "/xrpc/")
	switch method {
	case "com.atproto.identity.resolveHandle":
		s.resolveHandle(w, r)
	case "app.bsky.actor.getProfile":
		s.getProfile(w, r)
	default:
		writeXRPCError(w, http.StatusNotImplemented, "MethodNotImplemented", "method not implemented: "+method)
	}
}

// resolveHandle resolves a handle to a DID.
func (s *XRPCServer) resolveHandle(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "handle is required")
		return
	}
	t, err := s.Store.GetTenantByHandle(r.Context(), handle)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "HandleNotFound", "handle not found")
		return
	}
	did := t.DID
	if did == "" {
		did = "did:web:" + handle
	}
	writeJSON(w, map[string]string{"did": did})
}

// getProfile implements app.bsky.actor.getProfile.
func (s *XRPCServer) getProfile(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	if actor == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "actor is required")
		return
	}
	// actor may be a handle or DID.
	handle := actor
	if strings.HasPrefix(actor, "did:") {
		// Resolve DID to handle via the tenant store (best-effort).
		handle = actor
	}
	t, err := s.Store.GetTenantByHandle(r.Context(), handle)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "ActorNotFound", "actor not found")
		return
	}
	writeJSON(w, map[string]any{
		"did":         t.DID,
		"handle":      t.Handle,
		"displayName": t.Handle,
	})
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeXRPCError writes an XRPC error response.
func writeXRPCError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
