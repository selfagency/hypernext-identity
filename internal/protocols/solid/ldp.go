package solid

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hypernext/identity/internal/storage"
	"github.com/hypernext/identity/internal/tenant"
)

// Server is the Solid LDP HTTP handler.
type Server struct {
	// Backend returns the storage backend for a tenant.
	Backend func(tenantID string) storage.Backend
	// ACL authorizes access.
	ACL ACLChecker
	// Tokens validates bearer tokens to derive the authenticated agent.
	Tokens TokenValidator
}

// containerType is the LDP BasicContainer link relation.
const containerType = `<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"`

// allowHeader lists the LDP methods this server implements.
const allowHeader = "GET, HEAD, OPTIONS, PUT, POST, DELETE"

// ServeHTTP handles LDP requests for the tenant in context.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	agent := s.agentFromRequest(r)
	backend := s.Backend(t.ID)
	// r.URL.Path starts with "/"; the storage key is the path without the
	// leading slash (the Prefixed backend rejects absolute keys).
	key := strings.TrimPrefix(r.URL.Path, "/")

	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r, backend, key, agent)
	case http.MethodHead:
		s.handleHead(w, r, backend, key, agent)
	case http.MethodOptions:
		s.handleOptions(w, r)
	case http.MethodPut:
		s.handlePut(w, r, backend, key, agent)
	case http.MethodPost:
		s.handlePost(w, r, backend, key, agent)
	case http.MethodDelete:
		s.handleDelete(w, r, backend, key, agent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGet serves a resource or container listing. Containers are identified
// by a trailing slash (Solid Protocol §3.1 URI Slash Semantics).
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanRead(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if strings.HasSuffix(key, "/") {
		s.serveContainer(w, r, backend, key)
		return
	}
	rc, blob, err := backend.Get(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = rc.Close() }()
	w.Header().Set("Content-Type", blob.ContentType)
	w.Header().Set("Allow", allowHeader)
	if _, err := io.Copy(w, rc); err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
}

// handleHead serves headers for a resource without a body (LDP HEAD).
func (s *Server) handleHead(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanRead(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rc, blob, err := backend.Get(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = rc.Close()
	w.Header().Set("Content-Type", blob.ContentType)
	w.Header().Set("Allow", allowHeader)
	w.WriteHeader(http.StatusOK)
}

// handleOptions returns the allowed methods (LDP OPTIONS).
func (s *Server) handleOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", allowHeader)
	w.WriteHeader(http.StatusOK)
}

// serveContainer lists the children of a container as Turtle.
func (s *Server) serveContainer(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string) {
	blobs, err := backend.List(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/turtle")
	w.Header().Set("Link", containerType)
	w.Header().Set("Allow", allowHeader)
	writeContainerTurtle(w, key, blobs)
}

// handlePut stores a resource at the exact key (LDP PUT).
func (s *Server) handlePut(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanWrite(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if _, err := backend.Put(r.Context(), key, bytes.NewReader(body), r.Header.Get("Content-Type")); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// handlePost creates a server-assigned child under a container (LDP POST).
// The child key is a random slug; the response carries its Location.
func (s *Server) handlePost(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanWrite(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	// The container key ends with "/"; the child is a random slug under it.
	child := key + newSlug()
	if _, err := backend.Put(r.Context(), child, bytes.NewReader(body), r.Header.Get("Content-Type")); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", "/"+child)
	w.WriteHeader(http.StatusCreated)
}

// handleDelete removes a resource.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanWrite(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := backend.Delete(r.Context(), key); err != nil {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// agentFromRequest derives the authenticated agent from the request. If a
// bearer token is present and valid, the subject becomes the agent's WebID;
// otherwise the public agent is used.
func (s *Server) agentFromRequest(r *http.Request) Agent {
	if s.Tokens == nil {
		return AgentFromRequest(r)
	}
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || auth[:7] != "Bearer " {
		return AgentFromRequest(r)
	}
	subject, err := s.Tokens.ValidateToken(r.Context(), auth[7:])
	if err != nil {
		return AgentFromRequest(r)
	}
	return Agent{WebID: subject}
}

// writeContainerTurtle renders a container listing as Turtle, escaping IRIs
// so keys with spaces or special characters do not produce invalid Turtle.
func writeContainerTurtle(w io.Writer, key string, blobs []storage.Blob) {
	base := strings.TrimSuffix(key, "/")
	_, _ = io.WriteString(w, "@prefix ldp: <http://www.w3.org/ns/ldp#>.\n\n")
	_, _ = io.WriteString(w, "<"+escapeIRI(base)+"> a ldp:BasicContainer.\n")
	for _, b := range blobs {
		_, _ = io.WriteString(w, "<"+escapeIRI(base+"/"+b.Key)+"> a ldp:Resource.\n")
	}
}

// escapeIRI percent-encodes characters not allowed in a Turtle IRI reference.
func escapeIRI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '/' || c == ':' || c == '#' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// newSlug returns a random URL-safe slug for a server-assigned child.
func newSlug() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
