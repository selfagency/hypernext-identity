package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMiddlewareSecurityHeaders verifies the security-headers middleware sets
// the expected headers (S12).
func TestMiddlewareSecurityHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(next)

	req := httptest.NewRequest("GET", "/", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if rec.Header().Get(hdr) == "" {
			t.Fatalf("missing security header %s", hdr)
		}
	}
}

// TestMiddlewarePanicRecovery verifies a panicking handler returns 500, not a
// crash (S12).
func TestMiddlewarePanicRecovery(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	h := recoverPanic(next)

	req := httptest.NewRequest("GET", "/", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic recovery = %d, want 500", rec.Code)
	}
}

// TestMiddlewareMaxBody verifies oversized request bodies are rejected with
// 413 (S10).
func TestMiddlewareMaxBody(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body so MaxBytesReader enforces the cap; a too-large body
		// surfaces as a read error.
		buf := make([]byte, 4096)
		if _, err := r.Body.Read(buf); err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := maxBody(next, 1024)

	// Small body passes.
	req := httptest.NewRequest("POST", "/", strings.NewReader("small"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("small body = %d, want 200", rec.Code)
	}

	// Oversized body -> 413.
	big := strings.Repeat("x", 2048)
	req2 := httptest.NewRequest("POST", "/", strings.NewReader(big))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, want 413", rec2.Code)
	}
}
