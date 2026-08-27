// Package hyperlink implements the tenant profile / link-in-bio page. It is
// a view over existing identity data plus a small profile config. The
// security-critical pieces are the ownership boundary (RequireSelf) and link
// URL validation (scheme allowlist to prevent stored XSS).
package hyperlink

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Link is a single profile link.
type Link struct {
	ID       string
	Position int
	Kind     string // "brand" | "custom"
	BrandKey string
	Label    string
	URL      string
	Visible  bool
}

// allowedSchemes are the only URL schemes permitted in profile links.
// javascript: and data: are never allowed (stored-XSS vector).
var allowedSchemes = map[string]bool{
	"https":  true,
	"http":   true, // dev-only
	"mailto": true,
}

// ValidateLinkURL enforces the scheme allowlist and rejects malformed URLs.
func ValidateLinkURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("hyperlink: url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("hyperlink: malformed url")
	}
	if !allowedSchemes[strings.ToLower(u.Scheme)] {
		return errors.New("hyperlink: url scheme not allowed")
	}
	// Reject javascript:/data: explicitly (defense in depth).
	if strings.HasPrefix(strings.ToLower(raw), "javascript:") || strings.HasPrefix(strings.ToLower(raw), "data:") {
		return errors.New("hyperlink: url scheme not allowed")
	}
	return nil
}

// RequireSelf is middleware that enforces the ownership boundary: the
// authenticated account must own the resource being edited. This is distinct
// from RequireAdmin — never let one implicitly satisfy the other.
type RequireSelf struct {
	// AccountID returns the authenticated account ID from the request.
	AccountID func(r *http.Request) string
	// ResourceOwnerID returns the owner of the resource being edited.
	ResourceOwnerID func(r *http.Request) string
}

// Middleware returns a handler that rejects requests where the authenticated
// account does not own the resource (IDOR protection).
func (m *RequireSelf) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountID := m.AccountID(r)
		if accountID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ownerID := m.ResourceOwnerID(r)
		if ownerID == "" {
			http.Error(w, "resource owner not found", http.StatusNotFound)
			return
		}
		if accountID != ownerID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
