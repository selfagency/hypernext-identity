package hyperlink

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestValidateLinkURL verifies the scheme allowlist.
func TestValidateLinkURL(t *testing.T) {
	valid := []string{
		"https://example.com",
		"http://example.com", // dev-only
		"mailto:alice@example.com",
	}
	for _, u := range valid {
		if err := ValidateLinkURL(u); err != nil {
			t.Fatalf("ValidateLinkURL(%q) = %v, want nil", u, err)
		}
	}
	invalid := []string{
		"",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"ftp://example.com",
		"not a url",
	}
	for _, u := range invalid {
		if err := ValidateLinkURL(u); err == nil {
			t.Fatalf("ValidateLinkURL(%q) = nil, want error", u)
		}
	}
}

// TestRequireSelf verifies the ownership boundary (IDOR protection).
func TestRequireSelf(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	m := &RequireSelf{
		AccountID:       func(r *http.Request) string { return r.Header.Get("X-Account") },
		ResourceOwnerID: func(r *http.Request) string { return r.Header.Get("X-Owner") },
	}
	h := m.Middleware(next)

	// Owner matches -> allowed.
	req := httptest.NewRequest("GET", "/edit", http.NoBody)
	req.Header.Set("X-Account", "alice")
	req.Header.Set("X-Owner", "alice")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner match = %d, want 200", rec.Code)
	}

	// Cross-account edit -> 403 (IDOR).
	req2 := httptest.NewRequest("GET", "/edit", http.NoBody)
	req2.Header.Set("X-Account", "alice")
	req2.Header.Set("X-Owner", "bob")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("cross-account = %d, want 403", rec2.Code)
	}

	// Unauthenticated -> 401.
	req3 := httptest.NewRequest("GET", "/edit", http.NoBody)
	req3.Header.Set("X-Owner", "alice")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec3.Code)
	}

	// Missing owner -> 404.
	req4 := httptest.NewRequest("GET", "/edit", http.NoBody)
	req4.Header.Set("X-Account", "alice")
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusNotFound {
		t.Fatalf("missing owner = %d, want 404", rec4.Code)
	}
}

// TestRendererHTML verifies the h-card HTML rendering.
func TestRendererHTML(t *testing.T) {
	r := &Renderer{GetProfile: func(handle string) (*Profile, error) {
		return &Profile{
			DisplayName: "Alice",
			Bio:         "Hello",
			Handle:      "alice.example.com",
			Published:   true,
			Links:       []Link{{Label: "Site", URL: "https://example.com", Visible: true}},
		}, nil
	}}
	req := httptest.NewRequest("GET", "/alice.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `class="h-card"`) {
		t.Fatalf("missing h-card: %q", body)
	}
	if !strings.Contains(body, `class="p-name"`) {
		t.Fatalf("missing p-name: %q", body)
	}
	if !strings.Contains(body, `rel="me"`) {
		t.Fatalf("missing rel=me link: %q", body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Fatalf("cache-control = %q", cc)
	}
}

// TestRendererJSON verifies JSON content negotiation.
func TestRendererJSON(t *testing.T) {
	r := &Renderer{GetProfile: func(handle string) (*Profile, error) {
		return &Profile{DisplayName: "Alice", Handle: "alice.example.com", Published: true}, nil
	}}
	req := httptest.NewRequest("GET", "/alice.example.com", http.NoBody)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), `"DisplayName":"Alice"`) {
		t.Fatalf("json body = %q", rec.Body.String())
	}
}

// TestRendererUnpublished404 verifies unpublished pages return a uniform 404.
func TestRendererUnpublished404(t *testing.T) {
	r := &Renderer{GetProfile: func(handle string) (*Profile, error) {
		return &Profile{DisplayName: "Alice", Published: false}, nil
	}}
	req := httptest.NewRequest("GET", "/alice.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unpublished = %d, want 404", rec.Code)
	}
}

// TestRendererUnknown404 verifies unknown handles return 404.
func TestRendererUnknown404(t *testing.T) {
	r := &Renderer{GetProfile: func(handle string) (*Profile, error) {
		return nil, nil
	}}
	req := httptest.NewRequest("GET", "/unknown.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown = %d, want 404", rec.Code)
	}
}

// TestRendererEmptyHandle verifies an empty handle is a 404.
func TestRendererEmptyHandle(t *testing.T) {
	r := &Renderer{GetProfile: func(handle string) (*Profile, error) { return nil, nil }}
	req := httptest.NewRequest("GET", "/", http.NoBody)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty handle = %d, want 404", rec.Code)
	}
}
