// Package remotestorage implements the remoteStorage protocol
// (draft-dejong-remotestorage). It provides a WebDAV-like storage tree with
// bearer-token scope enforcement, CORS, and ETag-based caching.
package remotestorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/tenant"
)

// TokenValidator validates a bearer token and returns the scopes it grants.
// The auth package implements this; the interface keeps remoteStorage
// decoupled and testable.
type TokenValidator interface {
	// ValidateToken returns the scopes for a bearer token, or an error if
	// the token is invalid.
	ValidateToken(ctx context.Context, token string) ([]string, error)
}

// Server is the remoteStorage HTTP handler.
type Server struct {
	// Backend returns the storage backend for a tenant.
	Backend func(tenantID string) storage.Backend
	// Tokens validates bearer tokens.
	Tokens TokenValidator
}

// ServeHTTP handles remoteStorage requests for the tenant in context.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}

	// CORS: remoteStorage clients are cross-origin by design.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, If-None-Match")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// All non-OPTIONS requests require a bearer token.
	scopes, err := s.authorize(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	backend := s.Backend(t.ID)
	// r.URL.Path starts with "/"; the storage key is the path without the
	// leading slash (the Prefixed backend rejects absolute keys).
	key := strings.TrimPrefix(r.URL.Path, "/")

	switch r.Method {
	case http.MethodPut:
		s.handlePut(w, r, backend, key, scopes)
	case http.MethodGet:
		s.handleGet(w, r, backend, key, scopes)
	case http.MethodDelete:
		s.handleDelete(w, r, backend, key, scopes)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePut stores a resource, requiring write scope. It enforces
// If-Match / If-None-Match preconditions against the current resource.
func (s *Server) handlePut(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, scopes []string) {
	if !hasScope(scopes, "rw") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	// Read current state for precondition evaluation.
	exists, currentETag := currentState(r.Context(), backend, key)
	if !evaluatePreconditions(w, r, exists, currentETag) {
		return
	}
	if _, err := backend.Put(r.Context(), key, bytes.NewReader(body), r.Header.Get("Content-Type")); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag(body))
	w.WriteHeader(http.StatusOK)
}

// handleGet serves a resource or folder listing, requiring read scope. It
// emits an ETag and honors If-None-Match for cache revalidation.
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, scopes []string) {
	if !hasScope(scopes, "r") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Folder listing: a trailing slash (or empty key) lists direct children.
	if key == "" || strings.HasSuffix(key, "/") {
		s.serveFolder(w, r, backend, key)
		return
	}
	rc, blob, err := backend.Get(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(rc)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	et := etag(body)
	w.Header().Set("ETag", et)
	w.Header().Set("Content-Type", blob.ContentType)
	if matchETagList(r.Header.Get("If-None-Match"), et) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

// handleDelete removes a resource, requiring write scope. It enforces
// If-Match / If-None-Match preconditions against the current resource.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, scopes []string) {
	if !hasScope(scopes, "rw") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	exists, currentETag := currentState(r.Context(), backend, key)
	if !evaluatePreconditions(w, r, exists, currentETag) {
		return
	}
	if err := backend.Delete(r.Context(), key); err != nil {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// serveFolder lists the direct children of a folder key as remoteStorage
// folder-description JSON-LD.
func (s *Server) serveFolder(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string) {
	blobs, err := backend.List(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	items := map[string]map[string]any{}
	for _, b := range blobs {
		rel := strings.TrimPrefix(b.Key, key)
		if rel == "" || strings.Contains(rel, "/") {
			continue // only direct children
		}
		// Compute the ETag by reading the child (Blob has no content hash).
		et := ""
		if rc, _, gerr := backend.Get(r.Context(), b.Key); gerr == nil {
			if cur, rerr := io.ReadAll(rc); rerr == nil {
				et = etag(cur)
			}
			_ = rc.Close()
		}
		items[rel] = map[string]any{
			"ETag":           et,
			"Content-Type":   b.ContentType,
			"Content-Length": b.Size,
		}
	}
	w.Header().Set("Content-Type", "application/ld+json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"@context": "http://remotestorage.io/spec/folder-description",
		"items":    items,
	})
}

// currentState reports whether key exists and its current ETag.
func currentState(ctx context.Context, backend storage.Backend, key string) (exists bool, currentETag string) {
	rc, _, err := backend.Get(ctx, key)
	if err != nil {
		return false, ""
	}
	defer func() { _ = rc.Close() }()
	cur, err := io.ReadAll(rc)
	if err != nil {
		return false, ""
	}
	return true, etag(cur)
}

// evaluatePreconditions checks If-Match / If-None-Match against the current
// resource state. It returns false (and writes the status) when a precondition
// fails.
func evaluatePreconditions(w http.ResponseWriter, r *http.Request, exists bool, currentETag string) bool {
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" {
		// "*" matches any existing resource; a list matches on equal ETag.
		if ifNoneMatch == "*" && exists {
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return false
		}
		if exists && matchETagList(ifNoneMatch, currentETag) {
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return false
		}
	}
	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" {
		if ifMatch == "*" {
			if !exists {
				http.Error(w, "precondition failed", http.StatusPreconditionFailed)
				return false
			}
		} else if !exists || !matchETagList(ifMatch, currentETag) {
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return false
		}
	}
	return true
}

// matchETagList reports whether the comma-separated ETag list (which may use
// weak W/ prefixes or "*") contains target.
func matchETagList(list, target string) bool {
	for _, cand := range strings.Split(list, ",") {
		cand = strings.TrimSpace(cand)
		if cand == "*" {
			return true
		}
		cand = strings.TrimPrefix(cand, "W/")
		if cand == target {
			return true
		}
	}
	return false
}

// authorize extracts and validates the bearer token.
func (s *Server) authorize(r *http.Request) ([]string, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || auth[:7] != "Bearer " {
		return nil, errNoToken
	}
	return s.Tokens.ValidateToken(r.Context(), auth[7:])
}

// hasScope reports whether scopes grants the required scope. remoteStorage
// scopes are hierarchical: "rw" implies "r" (read+write grants read).
func hasScope(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required {
			return true
		}
		// "rw" satisfies the "r" requirement.
		if required == "r" && s == "rw" {
			return true
		}
	}
	return false
}

// etag computes a strong ETag from content.
func etag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

var errNoToken = errNoTokenType{}

type errNoTokenType struct{}

func (errNoTokenType) Error() string { return "no bearer token" }
