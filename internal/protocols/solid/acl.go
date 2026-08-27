// Package solid implements a Solid Pod (LDP subset): WebID profile docs,
// basic container CRUD, and ACL enforcement.
package solid

import (
	"context"
	"net/http"
)

// Agent identifies the authenticated requester (a WebID or the public agent).
type Agent struct {
	// WebID is the authenticated user's WebID, or "" for unauthenticated.
	WebID string
}

// TokenValidator validates a bearer token and returns the authenticated
// subject (used to derive the agent's WebID). The wiring package implements
// this; the interface keeps the LDP handler decoupled and testable.
type TokenValidator interface {
	// ValidateToken returns the subject for a bearer token, or an error if
	// the token is invalid.
	ValidateToken(ctx context.Context, token string) (string, error)
}

// ACLChecker authorizes access to resources. The storage phase wires a real
// implementation; the interface keeps the LDP handler decoupled and testable.
type ACLChecker interface {
	// CanRead reports whether agent may read resource.
	CanRead(ctx context.Context, resource string, agent Agent) bool
	// CanWrite reports whether agent may write resource.
	CanWrite(ctx context.Context, resource string, agent Agent) bool
}

// PublicAgent is the unauthenticated agent.
var PublicAgent = Agent{}

// AgentFromRequest extracts the agent from an authenticated request. The
// auth phase wires real token introspection; for now it returns the public
// agent unless a WebID is present in the request context.
func AgentFromRequest(r *http.Request) Agent {
	if webID, ok := r.Context().Value(webIDCtxKey{}).(string); ok && webID != "" {
		return Agent{WebID: webID}
	}
	return PublicAgent
}

type webIDCtxKey struct{}

// WithWebID returns a context carrying the authenticated WebID.
func WithWebID(ctx context.Context, webID string) context.Context {
	return context.WithValue(ctx, webIDCtxKey{}, webID)
}
