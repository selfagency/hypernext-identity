package moderation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hypernext/identity/internal/storage"
)

// TestTakedown verifies a takedown deletes the resource and logs it.
func TestTakedown(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	ctx := context.Background()
	if _, err := fs.Put(ctx, "posts/1", strings.NewReader("data"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	log := &MemoryAuditLog{}
	h := &TakedownHandler{Backend: func(string) storage.Backend { return fs }, Log: log}

	form := url.Values{"resource": {"posts/1"}, "reason": {"spam"}, "tenant": {"t1"}}
	req := httptest.NewRequest("POST", "/moderation/takedown", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Resource deleted.
	if _, _, err := fs.Get(ctx, "posts/1"); err == nil {
		t.Fatal("resource should be deleted")
	}
	// Audit logged.
	entries, _ := log.List(ctx, 10)
	if len(entries) != 1 || entries[0].Action != "takedown" || entries[0].Resource != "posts/1" {
		t.Fatalf("audit entries = %+v", entries)
	}
}

// TestTakedownMissingResource verifies a missing resource is a 400.
func TestTakedownMissingResource(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	h := &TakedownHandler{Backend: func(string) storage.Backend { return fs }, Log: &MemoryAuditLog{}}
	form := url.Values{"reason": {"spam"}, "tenant": {"t1"}}
	req := httptest.NewRequest("POST", "/moderation/takedown", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestTakedownMissingReason verifies a missing reason is a 400.
func TestTakedownMissingReason(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	h := &TakedownHandler{Backend: func(string) storage.Backend { return fs }, Log: &MemoryAuditLog{}}
	form := url.Values{"resource": {"posts/1"}, "tenant": {"t1"}}
	req := httptest.NewRequest("POST", "/moderation/takedown", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestTakedownNotFound verifies a missing resource returns 404.
func TestTakedownNotFound(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	h := &TakedownHandler{Backend: func(string) storage.Backend { return fs }, Log: &MemoryAuditLog{}}
	form := url.Values{"resource": {"missing"}, "reason": {"spam"}, "tenant": {"t1"}}
	req := httptest.NewRequest("POST", "/moderation/takedown", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestTakedownMethodNotAllowed verifies non-POST is rejected.
func TestTakedownMethodNotAllowed(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	h := &TakedownHandler{Backend: func(string) storage.Backend { return fs }, Log: &MemoryAuditLog{}}
	req := httptest.NewRequest("GET", "/moderation/takedown", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestMemoryAuditLogList verifies audit log listing.
func TestMemoryAuditLogList(t *testing.T) {
	log := &MemoryAuditLog{}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = log.Append(ctx, AuditEntry{Action: "takedown", Resource: "r"})
	}
	entries, _ := log.List(ctx, 3)
	if len(entries) != 3 {
		t.Fatalf("list = %d, want 3", len(entries))
	}
	// Limit > len returns all.
	all, _ := log.List(ctx, 100)
	if len(all) != 5 {
		t.Fatalf("list all = %d, want 5", len(all))
	}
}

// TestToSGate verifies the gate blocks unaccepted tenants.
func TestToSGate(t *testing.T) {
	store := NewMemoryToSStore()
	gate := &ToSGate{Store: store}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := gate.Middleware(next)

	// Unaccepted tenant -> 403.
	req := httptest.NewRequest("GET", "/data", http.NoBody)
	req.URL.RawQuery = "tenant=t1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unaccepted = %d, want 403", rec.Code)
	}

	// Accept, then allowed.
	if err := store.Accept(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest("GET", "/data", http.NoBody)
	req2.URL.RawQuery = "tenant=t1"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("accepted = %d, want 200", rec2.Code)
	}
}

// TestToSGateAllowsAcceptEndpoint verifies the ToS endpoint bypasses the gate.
func TestToSGateAllowsAcceptEndpoint(t *testing.T) {
	store := NewMemoryToSStore()
	gate := &ToSGate{Store: store}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := gate.Middleware(next)

	req := httptest.NewRequest("POST", "/admin/tos", http.NoBody)
	req.URL.RawQuery = "tenant=t1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tos endpoint = %d, want 200", rec.Code)
	}
}

// TestAcceptHandler verifies ToS acceptance.
func TestAcceptHandler(t *testing.T) {
	store := NewMemoryToSStore()
	h := &AcceptHandler{Store: store}
	form := url.Values{"tenant": {"t1"}}
	req := httptest.NewRequest("POST", "/admin/tos", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	accepted, _ := store.Accepted(context.Background(), "t1")
	if !accepted {
		t.Fatal("tenant should have accepted ToS")
	}
}

// TestAcceptHandlerMissingTenant verifies a missing tenant is a 400.
func TestAcceptHandlerMissingTenant(t *testing.T) {
	h := &AcceptHandler{Store: NewMemoryToSStore()}
	req := httptest.NewRequest("POST", "/admin/tos", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// failingAuditLog returns an error on Append.
type failingAuditLog struct{}

func (failingAuditLog) Append(context.Context, AuditEntry) error { return errors.New("append failed") }

func (failingAuditLog) List(context.Context, int) ([]AuditEntry, error) {
	return nil, errors.New("list failed")
}

// TestTakedownAuditError verifies an audit log error returns 500.
func TestTakedownAuditError(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	ctx := context.Background()
	if _, err := fs.Put(ctx, "posts/1", strings.NewReader("data"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	h := &TakedownHandler{Backend: func(string) storage.Backend { return fs }, Log: failingAuditLog{}}
	form := url.Values{"resource": {"posts/1"}, "reason": {"spam"}, "tenant": {"t1"}}
	req := httptest.NewRequest("POST", "/moderation/takedown", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// failingToSStore returns an error on Accepted/Accept.
type failingToSStore struct{}

func (failingToSStore) Accepted(context.Context, string) (bool, error) {
	return false, errors.New("accepted failed")
}
func (failingToSStore) Accept(context.Context, string) error { return errors.New("accept failed") }

// TestToSGateStoreError verifies a ToS store error returns 500.
func TestToSGateStoreError(t *testing.T) {
	gate := &ToSGate{Store: failingToSStore{}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := gate.Middleware(next)
	req := httptest.NewRequest("GET", "/data", http.NoBody)
	req.URL.RawQuery = "tenant=t1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestAcceptHandlerMethodNotAllowed verifies non-POST is rejected.
func TestAcceptHandlerMethodNotAllowed(t *testing.T) {
	h := &AcceptHandler{Store: NewMemoryToSStore()}
	req := httptest.NewRequest("GET", "/admin/tos", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestAcceptHandlerStoreError verifies a store error returns 500.
func TestAcceptHandlerStoreError(t *testing.T) {
	h := &AcceptHandler{Store: failingToSStore{}}
	form := url.Values{"tenant": {"t1"}}
	req := httptest.NewRequest("POST", "/admin/tos", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
