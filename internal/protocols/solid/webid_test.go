package solid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServeWebID verifies the WebID profile document.
func TestServeWebID(t *testing.T) {
	cfg := WebIDConfig{
		Handle:       "alice.example.com",
		IdentityHost: "id.example.com",
		StorageRoot:  "https://alice.example.com/storage",
	}
	req := httptest.NewRequest("GET", "/profile", http.NoBody)
	rec := httptest.NewRecorder()
	ServeWebID(cfg).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/turtle" {
		t.Fatalf("content-type = %q, want text/turtle", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "foaf:Person") {
		t.Fatalf("body missing foaf:Person: %q", body)
	}
	if !strings.Contains(body, "solid:oidcIssuer <https://id.example.com>") {
		t.Fatalf("body missing oidcIssuer: %q", body)
	}
	if !strings.Contains(body, "solid:storage <https://alice.example.com/storage>") {
		t.Fatalf("body missing storage: %q", body)
	}
}
