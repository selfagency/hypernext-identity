package solid

import (
	"bytes"
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
}

// containerType is the LDP BasicContainer link relation.
const containerType = `<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"`

// ServeHTTP handles LDP requests for the tenant in context.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	agent := AgentFromRequest(r)
	backend := s.Backend(t.ID)
	key := r.URL.Path

	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r, backend, key, agent)
	case http.MethodPut, http.MethodPost:
		s.handleWrite(w, r, backend, key, agent)
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
	w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE")
	if _, err := io.Copy(w, rc); err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
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
	w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE")
	writeContainerTurtle(w, key, blobs)
}

// handleWrite stores a resource (PUT) or creates a child (POST).
func (s *Server) handleWrite(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
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

// writeContainerTurtle renders a container listing as Turtle.
func writeContainerTurtle(w io.Writer, key string, blobs []storage.Blob) {
	base := strings.TrimSuffix(key, "/")
	_, _ = io.WriteString(w, "@prefix ldp: <http://www.w3.org/ns/ldp#>.\n\n")
	_, _ = io.WriteString(w, "<"+base+"> a ldp:BasicContainer.\n")
	for _, b := range blobs {
		_, _ = io.WriteString(w, "<"+base+"/"+b.Key+"> a ldp:Resource.\n")
	}
}
