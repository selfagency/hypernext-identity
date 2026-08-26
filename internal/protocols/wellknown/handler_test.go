package wellknown

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func testHandlers() Handlers {
	return Handlers{
		HCard: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>h-card</html>"))
		},
		Actor: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/activity+json")
			w.Write([]byte(`{"type":"Person"}`))
		},
		DIDDoc: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/did+json")
			w.Write([]byte(`{"id":"did:web:alice.example.com"}`))
		},
	}
}

// TestProfileHandlerActivityPub verifies Accept: application/activity+json.
func TestProfileHandlerActivityPub(t *testing.T) {
	req := httptest.NewRequest("GET", "/", http.NoBody)
	req.Header.Set("Accept", "application/activity+json")
	rec := httptest.NewRecorder()
	ProfileHandler(testHandlers()).ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/activity+json" {
		t.Fatalf("content-type = %q, want application/activity+json", ct)
	}
	if rec.Body.String() != `{"type":"Person"}` {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestProfileHandlerDIDDoc verifies Accept: application/did+json.
func TestProfileHandlerDIDDoc(t *testing.T) {
	req := httptest.NewRequest("GET", "/profile", http.NoBody)
	req.Header.Set("Accept", "application/did+json")
	rec := httptest.NewRecorder()
	ProfileHandler(testHandlers()).ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/did+json" {
		t.Fatalf("content-type = %q, want application/did+json", ct)
	}
	if rec.Body.String() != `{"id":"did:web:alice.example.com"}` {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestProfileHandlerHCard verifies the default (no Accept) is h-card.
func TestProfileHandlerHCard(t *testing.T) {
	req := httptest.NewRequest("GET", "/profile", http.NoBody)
	rec := httptest.NewRecorder()
	ProfileHandler(testHandlers()).ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if rec.Body.String() != "<html>h-card</html>" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestProfileHandlerBrowserAccept verifies a browser Accept falls back to h-card.
func TestProfileHandlerBrowserAccept(t *testing.T) {
	req := httptest.NewRequest("GET", "/profile", http.NoBody)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	rec := httptest.NewRecorder()
	ProfileHandler(testHandlers()).ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
}
