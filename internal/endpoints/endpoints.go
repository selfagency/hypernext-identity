// Package endpoints implements the public (unauthenticated) HTTP endpoints
// for the identity server: key hosting (.keys/.gpg/WKD) and the proofs
// registry (/.well-known/proofs). These serve data from the SQLite store.
package endpoints

import (
	"crypto/sha1"
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
// The tenant is derived from the request host (set by the tenant middleware),
// never from the URL path — a path handle must not override the host-derived
// tenant (C4).
func (h *KeysHandler) serveKeys(w http.ResponseWriter, r *http.Request, keyType string) {
	// The tenant is the request host (the tenant middleware resolved it).
	tenantID := strings.Split(r.Host, ":")[0]
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

// serveWKD serves a single key by z-base-32 hash of the localpart. The hash
// is the last path segment; we look up the key whose identity localpart hashes
// to it, and 404 on a mismatch (S7).
func (h *KeysHandler) serveWKD(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	hash := parts[len(parts)-1]
	// Resolve tenant from the host header (WKD is per-domain).
	tenantID := strings.Split(r.Host, ":")[0]
	keys, err := h.Store.ListPublicKeys(r.Context(), tenantID, "pgp")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range keys {
		k := &keys[i]
		if k.RevokedAt != nil {
			continue
		}
		// Match the requested hash against the key's localpart hash.
		if wkdHash(localpartFromKey(k)) == hash {
			w.Header().Set("Content-Type", "application/pgp-keys")
			// #nosec G705 — plaintext key output, not HTML.
			_, _ = w.Write([]byte(k.KeyMaterial))
			return
		}
	}
	http.NotFound(w, r)
}

// localpartFromKey derives the localpart (email user) from a public key's
// account ID. The account ID is the localpart for the tenant host.
func localpartFromKey(k *store.PublicKey) string {
	return k.AccountID
}

// wkdHash computes the z-base-32 WKD hash of a localpart (SHA-1, then
// z-base-32 encoding per the WKD spec). SHA-1 is mandated by the WKD spec
// for the localpart hash; it is not used for security here.
func wkdHash(localpart string) string {
	// #nosec G401
	sum := sha1.Sum([]byte(localpart))
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var out []byte
	// Encode the 20-byte SHA-1 as z-base-32 (32 chars).
	for i := 0; i < len(sum); i += 5 {
		var buf [8]byte
		bits := 0
		val := 0
		for j := 0; j < 5 && i+j < len(sum); j++ {
			val = (val << 8) | int(sum[i+j])
			bits += 8
		}
		for j := 7; j >= 0; j-- {
			if bits >= 5 {
				buf[j] = alphabet[val&0x1f]
				val >>= 5
				bits -= 5
			}
		}
		for j := 0; j < 8; j++ {
			out = append(out, buf[7-j])
		}
	}
	return string(out)
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
