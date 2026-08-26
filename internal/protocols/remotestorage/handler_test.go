package remotestorage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hypernext/identity/internal/storage"
	"github.com/hypernext/identity/internal/tenant"
)

// fakeTokens validates tokens against a fixed map.
type fakeTokens struct {
	scopes map[string][]string
}

func (f fakeTokens) ValidateToken(_ context.Context, token string) ([]string, error) {
	if s, ok := f.scopes[token]; ok {
		return s, nil
	}
	return nil, errors.New("invalid token")
}

// newTestServer builds a remoteStorage server with an in-memory FS backend.
func newTestServer(t *testing.T, scopes map[string][]string) (*Server, *storage.FS) {
	t.Helper()
	fs := &storage.FS{Root: t.TempDir()}
	return &Server{
		Backend: func(string) storage.Backend { return fs },
		Tokens:  fakeTokens{scopes: scopes},
	}, fs
}

// withTenant wraps a handler with the tenant middleware.
func withTenant(h http.Handler, handle string) http.Handler {
	store := fakeTenantStore{tenants: map[string]*tenant.Tenant{handle: {ID: "t1", Handle: handle}}}
	return tenant.Middleware(store)(h)
}

type fakeTenantStore struct{ tenants map[string]*tenant.Tenant }

func (f fakeTenantStore) FindByHost(_ context.Context, host string) (*tenant.Tenant, error) {
	t, ok := f.tenants[host]
	if !ok {
		return nil, tenant.ErrNotFound
	}
	return t, nil
}

// TestCORSPreflight verifies OPTIONS returns CORS headers.
func TestCORSPreflight(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	h := withTenant(srv, "alice.example.com")
	req := httptest.NewRequest("OPTIONS", "/docs/", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ao := rec.Header().Get("Access-Control-Allow-Origin"); ao != "*" {
		t.Fatalf("allow-origin = %q, want *", ao)
	}
}

// TestPutGetDeleteRoundTrip verifies the full storage lifecycle.
func TestPutGetDeleteRoundTrip(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"tok": {"rw"}})
	h := withTenant(srv, "alice.example.com")

	// PUT
	putReq := httptest.NewRequest("PUT", "/docs/hello.txt", strings.NewReader("hello world"))
	putReq.Host = "alice.example.com"
	putReq.Header.Set("Authorization", "Bearer tok")
	putReq.Header.Set("Content-Type", "text/plain")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", putRec.Code)
	}
	if et := putRec.Header().Get("ETag"); et == "" {
		t.Fatal("PUT missing ETag")
	}

	// GET
	getReq := httptest.NewRequest("GET", "/docs/hello.txt", http.NoBody)
	getReq.Host = "alice.example.com"
	getReq.Header.Set("Authorization", "Bearer tok")
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getRec.Code)
	}
	if body := getRec.Body.String(); body != "hello world" {
		t.Fatalf("GET body = %q, want hello world", body)
	}
	if ct := getRec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("GET content-type = %q, want text/plain", ct)
	}

	// DELETE
	delReq := httptest.NewRequest("DELETE", "/docs/hello.txt", http.NoBody)
	delReq.Host = "alice.example.com"
	delReq.Header.Set("Authorization", "Bearer tok")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200", delRec.Code)
	}

	// GET after delete -> 404
	getReq2 := httptest.NewRequest("GET", "/docs/hello.txt", http.NoBody)
	getReq2.Host = "alice.example.com"
	getReq2.Header.Set("Authorization", "Bearer tok")
	getRec2 := httptest.NewRecorder()
	h.ServeHTTP(getRec2, getReq2)
	if getRec2.Code != http.StatusNotFound {
		t.Fatalf("GET after delete = %d, want 404", getRec2.Code)
	}
}

// TestUnauthorized verifies missing/invalid tokens are rejected.
func TestUnauthorized(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"tok": {"rw"}})
	h := withTenant(srv, "alice.example.com")

	// No token
	req := httptest.NewRequest("GET", "/docs/x", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", rec.Code)
	}

	// Invalid token
	req2 := httptest.NewRequest("GET", "/docs/x", http.NoBody)
	req2.Host = "alice.example.com"
	req2.Header.Set("Authorization", "Bearer bad")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d, want 401", rec2.Code)
	}
}

// TestScopeEnforcement verifies read/write scope requirements.
func TestScopeEnforcement(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"readonly": {"r"}})
	h := withTenant(srv, "alice.example.com")

	// Read-only token can GET but not PUT.
	putReq := httptest.NewRequest("PUT", "/docs/x", strings.NewReader("data"))
	putReq.Host = "alice.example.com"
	putReq.Header.Set("Authorization", "Bearer readonly")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusForbidden {
		t.Fatalf("read-only PUT status = %d, want 403", putRec.Code)
	}

	getReq := httptest.NewRequest("GET", "/docs/x", http.NoBody)
	getReq.Host = "alice.example.com"
	getReq.Header.Set("Authorization", "Bearer readonly")
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("read-only GET missing = %d, want 404", getRec.Code)
	}
}

// TestETagStable verifies identical content yields the same ETag.
func TestETagStable(t *testing.T) {
	a := etag([]byte("same"))
	b := etag([]byte("same"))
	if a != b {
		t.Fatal("identical content should have identical ETag")
	}
	if etag([]byte("a")) == etag([]byte("b")) {
		t.Fatal("different content should have different ETag")
	}
}

// TestNoTenant verifies a missing tenant is a 404.
func TestNoTenant(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"tok": {"rw"}})
	req := httptest.NewRequest("GET", "/docs/x", http.NoBody)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no tenant status = %d, want 404", rec.Code)
	}
}

// TestMethodNotAllowed verifies unsupported methods are rejected.
func TestMethodNotAllowed(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"tok": {"rw"}})
	h := withTenant(srv, "alice.example.com")
	req := httptest.NewRequest("POST", "/docs/x", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

// TestDeleteMissing verifies DELETE of a missing resource is a 404.
func TestDeleteMissing(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"tok": {"rw"}})
	h := withTenant(srv, "alice.example.com")
	req := httptest.NewRequest("DELETE", "/docs/missing", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE missing status = %d, want 404", rec.Code)
	}
}

// TestErrNoToken verifies the error message.
func TestErrNoToken(t *testing.T) {
	if errNoToken.Error() != "no bearer token" {
		t.Fatalf("errNoToken = %q, want 'no bearer token'", errNoToken.Error())
	}
}

// failingBackend returns errors on every operation.
type failingBackend struct{}

func (failingBackend) Put(context.Context, string, io.Reader, string) (storage.Blob, error) {
	return storage.Blob{}, errors.New("put failed")
}

func (failingBackend) Get(context.Context, string) (io.ReadCloser, storage.Blob, error) {
	return nil, storage.Blob{}, errors.New("get failed")
}
func (failingBackend) Delete(context.Context, string) error { return errors.New("delete failed") }
func (failingBackend) List(context.Context, string) ([]storage.Blob, error) {
	return nil, errors.New("list failed")
}

// TestStorageErrors verifies storage backend failures map to 500/404.
func TestStorageErrors(t *testing.T) {
	srv := &Server{
		Backend: func(string) storage.Backend { return failingBackend{} },
		Tokens:  fakeTokens{scopes: map[string][]string{"tok": {"rw"}}},
	}
	h := withTenant(srv, "alice.example.com")

	// PUT storage error -> 500
	putReq := httptest.NewRequest("PUT", "/docs/x", strings.NewReader("data"))
	putReq.Host = "alice.example.com"
	putReq.Header.Set("Authorization", "Bearer tok")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT storage error = %d, want 500", putRec.Code)
	}

	// GET storage error -> 404 (backend.Get error treated as not found)
	getReq := httptest.NewRequest("GET", "/docs/x", http.NoBody)
	getReq.Host = "alice.example.com"
	getReq.Header.Set("Authorization", "Bearer tok")
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("GET storage error = %d, want 404", getRec.Code)
	}

	// DELETE storage error -> 404
	delReq := httptest.NewRequest("DELETE", "/docs/x", http.NoBody)
	delReq.Host = "alice.example.com"
	delReq.Header.Set("Authorization", "Bearer tok")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusNotFound {
		t.Fatalf("DELETE storage error = %d, want 404", delRec.Code)
	}
}
