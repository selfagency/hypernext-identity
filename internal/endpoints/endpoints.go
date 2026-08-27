// Package endpoints implements the public (unauthenticated) HTTP endpoints
// for the identity server: key hosting (.keys/.gpg/WKD) and the proofs
// registry (/.well-known/proofs). These serve data from the SQLite store.
package endpoints

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/hypernext/identity/internal/store"
)

// KeysHandler serves the public key endpoints.
type KeysHandler struct {
	Store *store.Store
}

// ServeHTTP routes .keys/.gpg/WKD/keys requests.
func (h *KeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, ".keys"):
		h.serveKeys(w, r, "ssh")
	case strings.HasSuffix(path, ".gpg"):
		h.serveKeys(w, r, "pgp")
	case strings.HasPrefix(path, "/.well-known/openpgpkey/hu/"):
		h.serveWKD(w, r)
	case path == "/keys":
		h.serveKeysPage(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveKeys serves the .keys/.gpg plaintext output (GitHub/GitLab convention).
func (h *KeysHandler) serveKeys(w http.ResponseWriter, r *http.Request, keyType string) {
	// Strip the ".keys" or ".gpg" suffix to get the handle.
	suffix := ".keys"
	if keyType == "pgp" {
		suffix = ".gpg"
	}
	handle := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), suffix)
	tenantID := handle // handle == tenant host
	keys, err := h.Store.ListPublicKeys(r.Context(), tenantID, keyType)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for i := range keys {
		k := &keys[i]
		if k.RevokedAt != nil {
			continue // revoked keys excluded from .keys/.gpg
		}
		// #nosec G705 -- plaintext key output, not HTML.
		_, _ = w.Write([]byte(k.KeyMaterial + "\n"))
	}
}

// serveWKD serves a single key by z-base-32 hash of the localpart.
func (h *KeysHandler) serveWKD(w http.ResponseWriter, r *http.Request) {
	// The hash is the last path segment; we look up by fingerprint match.
	// For simplicity, serve the tenant's first active PGP key.
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	hash := parts[len(parts)-1]
	_ = hash
	// Resolve tenant from the host header (WKD is per-domain).
	tenantID := r.Host
	keys, err := h.Store.ListPublicKeys(r.Context(), tenantID, "pgp")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range keys {
		k := &keys[i]
		if k.RevokedAt == nil {
			w.Header().Set("Content-Type", "application/pgp-keys")
			// #nosec G705 — plaintext key output, not HTML.
			_, _ = w.Write([]byte(k.KeyMaterial))
			return
		}
	}
	http.NotFound(w, r)
}

// serveKeysPage serves a human-readable keys page.
func (h *KeysHandler) serveKeysPage(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Host
	keys, err := h.Store.ListPublicKeys(r.Context(), tenantID, "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = keysPageTemplate.Execute(w, keys)
}

var keysPageTemplate = template.Must(template.New("keys").Parse(`<html><body><h1>Public Keys</h1><ul>
{{range .}}<li>{{.KeyType}} {{.Fingerprint}} ({{if .RevokedAt}}revoked{{else}}active{{end}})</li>
{{end}}</ul></body></html>`))

// ProofsHandler serves the /.well-known/proofs JSON endpoint.
type ProofsHandler struct {
	Store *store.Store
}

// ServeHTTP serves the machine-readable verified claims JSON.
func (h *ProofsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Host
	claims, err := h.Store.VerifiedProofClaims(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := struct {
		Anchor struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"anchor"`
		Claims []struct {
			Service    string `json:"service"`
			Location   string `json:"location"`
			Status     string `json:"status"`
			VerifiedAt string `json:"verifiedAt,omitempty"`
		} `json:"claims"`
	}{Claims: []struct {
		Service    string `json:"service"`
		Location   string `json:"location"`
		Status     string `json:"status"`
		VerifiedAt string `json:"verifiedAt,omitempty"`
	}{}}
	if len(claims) > 0 {
		out.Anchor.Type = claims[0].AnchorType
		out.Anchor.Value = claims[0].AnchorValue
	}
	for i := range claims {
		c := &claims[i]
		verifiedAt := ""
		if c.LastCheckedAt != nil {
			verifiedAt = c.LastCheckedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		out.Claims = append(out.Claims, struct {
			Service    string `json:"service"`
			Location   string `json:"location"`
			Status     string `json:"status"`
			VerifiedAt string `json:"verifiedAt,omitempty"`
		}{Service: c.Service, Location: c.ClaimLocation, Status: c.Status, VerifiedAt: verifiedAt})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
