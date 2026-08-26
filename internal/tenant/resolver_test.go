package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeStore struct{ tenants map[string]*Tenant }

func (f fakeStore) FindByHost(_ context.Context, host string) (*Tenant, error) {
	t, ok := f.tenants[host]
	if !ok {
		return nil, ErrNotFound
	}
	return t, nil
}

func TestMiddleware_ResolvesKnownTenant(t *testing.T) {
	store := fakeStore{tenants: map[string]*Tenant{
		"alice.example.com": {ID: "t1", Handle: "alice.example.com"},
	}}
	var captured *Tenant
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = FromContext(r.Context())
	})
	req := httptest.NewRequest("GET", "https://alice.example.com/", nil)
	Middleware(store)(next).ServeHTTP(httptest.NewRecorder(), req)

	if captured == nil || captured.ID != "t1" {
		t.Fatalf("expected tenant t1, got %+v", captured)
	}
}

func TestMiddleware_RejectsUnknownHost(t *testing.T) {
	store := fakeStore{tenants: map[string]*Tenant{}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://ghost.example.com/", nil)
	Middleware(store)(http.NotFoundHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestMiddleware_StripsPortFromHost(t *testing.T) {
	store := fakeStore{tenants: map[string]*Tenant{
		"alice.example.com": {ID: "t1", Handle: "alice.example.com"},
	}}
	var captured *Tenant
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = FromContext(r.Context())
	})
	req := httptest.NewRequest("GET", "https://alice.example.com:8443/", nil)
	Middleware(store)(next).ServeHTTP(httptest.NewRecorder(), req)

	if captured == nil || captured.ID != "t1" {
		t.Fatalf("expected tenant t1 with port stripped, got %+v", captured)
	}
}

func TestFromContext_EmptyContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("expected no tenant in empty context")
	}
}
