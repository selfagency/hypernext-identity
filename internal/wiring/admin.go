package wiring

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// AdminGuard authorizes admin-only routes. It validates a bearer access
// token, resolves the subject to a user, and requires the user to be an
// instance admin. It is deliberately separate from RequireSelf: an admin
// token does not implicitly grant self-service resource access, and a
// self-service token does not grant admin access (AGENTS.md boundary rule).
type AdminGuard struct {
	Key   *rsa.PrivateKey
	Store *store.Store
}

// Authorize reports whether the request carries a valid admin bearer token.
func (g *AdminGuard) Authorize(r *http.Request) bool {
	token := bearerToken(r)
	if token == "" {
		return false
	}
	claims, err := auth.ValidateAccessToken(g.Key, token)
	if err != nil {
		return false
	}
	u, err := g.Store.UserByID(r.Context(), claims.Subject)
	if err != nil {
		return false
	}
	return u.IsAdmin
}

// Middleware wraps a handler, rejecting non-admin requests with 401/403.
func (g *AdminGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Authorize(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken extracts the bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
