package webfinger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hypernext/identity/internal/tenant"
)

// fakeStore resolves a fixed set of hosts to tenants.
type fakeStore struct{ tenants map[string]*tenant.Tenant }

func (f fakeStore) FindByHost(_ context.Context, host string) (*tenant.Tenant, error) {
	t, ok := f.tenants[host]
	if !ok {
		return nil, tenant.ErrNotFound
	}
	return t, nil
}

// withTenant wraps a handler with the real tenant middleware for a host.
func withTenant(h http.Handler, t *tenant.Tenant) http.Handler {
	store := fakeStore{tenants: map[string]*tenant.Tenant{t.Handle: t}}
	return tenant.Middleware(store)(h)
}

func testConfig() Config {
	return Config{
		IdentityHost: "id.example.com",
		StorageRoot:  "https://alice.example.com/storage",
		ActorURL:     "https://alice.example.com/actor",
	}
}

// TestHandlerServesJRD verifies a valid JRD response with all links.
func TestHandlerServesJRD(t *testing.T) {
	h := withTenant(Handler(testConfig()), &tenant.Tenant{ID: "t1", Handle: "alice.example.com"})
	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:alice@example.com", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/jrd+json" {
		t.Fatalf("content-type = %q, want application/jrd+json", ct)
	}

	var jrd JRD
	if err := json.Unmarshal(rec.Body.Bytes(), &jrd); err != nil {
		t.Fatalf("invalid JRD JSON: %v", err)
	}
	if jrd.Subject != "acct:alice@example.com" {
		t.Fatalf("subject = %q, want acct:alice@example.com", jrd.Subject)
	}
	if len(jrd.Aliases) != 1 || jrd.Aliases[0] != "https://alice.example.com" {
		t.Fatalf("aliases = %v, want [https://alice.example.com]", jrd.Aliases)
	}
	if len(jrd.Links) != 3 {
		t.Fatalf("links = %d, want 3", len(jrd.Links))
	}
}

// TestHandlerRequiresResource verifies a missing resource param is a 400.
func TestHandlerRequiresResource(t *testing.T) {
	h := withTenant(Handler(testConfig()), &tenant.Tenant{ID: "t1", Handle: "alice.example.com"})
	req := httptest.NewRequest("GET", "/.well-known/webfinger", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestHandlerNoTenant verifies a missing tenant is a 404.
func TestHandlerNoTenant(t *testing.T) {
	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:alice@example.com", http.NoBody)
	rec := httptest.NewRecorder()
	Handler(testConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestHandlerLinks verifies the specific link relations are present.
func TestHandlerLinks(t *testing.T) {
	h := withTenant(Handler(testConfig()), &tenant.Tenant{ID: "t1", Handle: "alice.example.com"})
	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:alice@example.com", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var jrd JRD
	if err := json.Unmarshal(rec.Body.Bytes(), &jrd); err != nil {
		t.Fatal(err)
	}

	rels := map[string]Link{}
	for _, l := range jrd.Links {
		rels[l.Rel] = l
	}

	// remoteStorage
	if l, ok := rels["http://tools.ietf.org/id/draft-dejong-remotestorage"]; !ok || l.Href != "https://alice.example.com/storage" {
		t.Fatalf("remoteStorage link = %+v", l)
	}
	// ActivityPub self
	if l, ok := rels["self"]; !ok || l.Type != "application/activity+json" || l.Href != "https://alice.example.com/actor" {
		t.Fatalf("activitypub link = %+v", l)
	}
	// OIDC issuer
	if l, ok := rels["http://openid.net/specs/connect/1.0/issuer"]; !ok || l.Href != "https://id.example.com" {
		t.Fatalf("oidc issuer link = %+v", l)
	}
}
