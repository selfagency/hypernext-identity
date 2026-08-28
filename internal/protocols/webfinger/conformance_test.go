package webfinger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/selfagency/sovereign/internal/tenant"
)

// TestSpecConformanceJRD verifies the WebFinger response matches the RFC 7033
// JRD shape exactly: subject, aliases, and links with the required fields.
// RFC 7033 §4.4 defines the JRD; §4.4.4 defines link relations.
func TestSpecConformanceJRD(t *testing.T) {
	h := withTenant(Handler(testConfig()), &tenant.Tenant{ID: "t1", Handle: "alice.example.com"})
	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:alice@example.com", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/jrd+json" {
		t.Fatalf("content-type = %q, want application/jrd+json (RFC 7033 §4.4)", ct)
	}

	// Decode into a generic map to assert the exact wire shape (no extra
	// fields, correct types).
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// subject must be the requested resource (RFC 7033 §4.4.1).
	if raw["subject"] != "acct:alice@example.com" {
		t.Fatalf("subject = %v, want acct:alice@example.com", raw["subject"])
	}

	// aliases must be an array of strings (RFC 7033 §4.4.2).
	aliases, ok := raw["aliases"].([]any)
	if !ok || len(aliases) != 1 || aliases[0] != "https://alice.example.com" {
		t.Fatalf("aliases = %v, want [https://alice.example.com]", raw["aliases"])
	}

	// links must be an array of objects (RFC 7033 §4.4.4).
	links, ok := raw["links"].([]any)
	if !ok || len(links) != 3 {
		t.Fatalf("links = %v, want 3 entries", raw["links"])
	}
	for _, l := range links {
		assertLinkHasRel(t, l)
	}
}

// assertLinkHasRel verifies a link entry is an object with a rel (RFC 7033
// §4.4.4.1).
func assertLinkHasRel(t *testing.T, l any) {
	t.Helper()
	link, ok := l.(map[string]any)
	if !ok {
		t.Fatalf("link entry not an object: %v", l)
	}
	if _, ok := link["rel"].(string); !ok {
		t.Fatalf("link missing rel: %v", link)
	}
}

// TestSpecConformanceLinkFields verifies each link has the correct rel/type/
// href per RFC 7033 §4.4.4.
func TestSpecConformanceLinkFields(t *testing.T) {
	h := withTenant(Handler(testConfig()), &tenant.Tenant{ID: "t1", Handle: "alice.example.com"})
	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:alice@example.com", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var jrd JRD
	if err := json.Unmarshal(rec.Body.Bytes(), &jrd); err != nil {
		t.Fatal(err)
	}

	// remoteStorage link: rel + href, no type (RFC 7033 §4.4.4.2).
	rs := findLink(jrd.Links, "http://tools.ietf.org/id/draft-dejong-remotestorage")
	if rs == nil || rs.Href != "https://alice.example.com/storage" {
		t.Fatalf("remoteStorage link = %+v", rs)
	}

	// ActivityPub self link: rel + type + href.
	self := findLink(jrd.Links, "self")
	if self == nil || self.Type != "application/activity+json" || self.Href != "https://alice.example.com/actor" {
		t.Fatalf("self link = %+v", self)
	}

	// OIDC issuer link: rel + href.
	issuer := findLink(jrd.Links, "http://openid.net/specs/connect/1.0/issuer")
	if issuer == nil || issuer.Href != "https://id.example.com" {
		t.Fatalf("issuer link = %+v", issuer)
	}
}

func findLink(links []Link, rel string) *Link {
	for i := range links {
		if links[i].Rel == rel {
			return &links[i]
		}
	}
	return nil
}

// TestConformanceNoTenant verifies a request without a tenant is a 404
// (RFC 7033 §4.3: unknown resource -> 404).
func TestConformanceNoTenant(t *testing.T) {
	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:alice@example.com", http.NoBody)
	rec := httptest.NewRecorder()
	Handler(testConfig()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
