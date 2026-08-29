// Package tenant resolves an incoming HTTP Host header to a tenant.
//
// Multi-tenancy is the foundation of the identity server: every protocol
// module (Solid, remoteStorage, atproto, WebFinger, OIDC) reads the tenant
// from the request context. There is no global state.
package tenant

import (
	"context"
	"errors"
	"net/http"
)

// Tenant is a single identity + data tenant, keyed by its handle (host).
type Tenant struct {
	ID        string // stable internal id
	Handle    string // e.g. "alice.example.com"
	DIDMethod string // "web" | "plc"
	DID       string
}

// Store resolves a host to a tenant.
type Store interface {
	FindByHost(ctx context.Context, host string) (*Tenant, error)
}

// ErrNotFound is returned by Store when no tenant matches the host.
var ErrNotFound = errors.New("tenant not found")

type ctxKey int

const tenantCtxKey ctxKey = 0

// Middleware resolves the tenant from r.Host and injects it into the
// request context. Unknown hosts get a 404.
func Middleware(store Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := NormalizeHost(r.Host)
			t, err := store.FindByHost(r.Context(), host)
			if err != nil {
				http.Error(w, "unknown tenant", http.StatusNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), tenantCtxKey, t)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext returns the tenant for the request, if present.
func FromContext(ctx context.Context) (*Tenant, bool) {
	t, ok := ctx.Value(tenantCtxKey).(*Tenant)
	return t, ok
}

// WithTenant returns a context carrying the given tenant.
func WithTenant(ctx context.Context, t *Tenant) context.Context {
	return context.WithValue(ctx, tenantCtxKey, t)
}
