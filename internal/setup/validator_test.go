package setup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestValidateAllPass verifies all checks pass with correct DNS + well-known.
func TestValidateAllPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("did:plc:abc123"))
	}))
	defer srv.Close()

	v := &Validator{
		HTTPClient: srv.Client(),
		LookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return []string{"did=did:plc:abc123"}, nil
		},
		Scheme: "http",
	}
	// Point the well-known check at the test server by using its host.
	checks := v.Validate(context.Background(), strings.TrimPrefix(srv.URL, "http://"))
	if !AllPass(checks) {
		t.Fatalf("checks = %+v, want all pass", checks)
	}
}

// TestValidateDNSTXTMissing verifies a missing DNS TXT record fails.
func TestValidateDNSTXTMissing(t *testing.T) {
	v := &Validator{
		HTTPClient: &http.Client{},
		LookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return nil, errors.New("no such host")
		},
	}
	checks := v.Validate(context.Background(), "alice.example.com")
	if AllPass(checks) {
		t.Fatalf("checks = %+v, want DNS failure", checks)
	}
	if checks[0].OK {
		t.Fatal("DNS TXT check should fail")
	}
}

// TestValidateDNSTXTNoDID verifies a TXT record without did= fails.
func TestValidateDNSTXTNoDID(t *testing.T) {
	v := &Validator{
		HTTPClient: &http.Client{},
		LookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return []string{"v=spf1 include:_spf.example.com"}, nil
		},
	}
	checks := v.Validate(context.Background(), "alice.example.com")
	if checks[0].OK {
		t.Fatal("DNS TXT check should fail without did= value")
	}
}

// TestValidateWellKnownDown verifies a failing well-known endpoint fails.
func TestValidateWellKnownDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := &Validator{
		HTTPClient: srv.Client(),
		LookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return []string{"did=did:plc:abc123"}, nil
		},
		Scheme: "http",
	}
	checks := v.Validate(context.Background(), strings.TrimPrefix(srv.URL, "http://"))
	if AllPass(checks) {
		t.Fatalf("checks = %+v, want well-known to fail", checks)
	}
	if checks[1].OK {
		t.Fatal("well-known check should fail on 500")
	}
}

// TestAllPass verifies AllPass logic.
func TestAllPass(t *testing.T) {
	if !AllPass([]Check{{OK: true}, {OK: true}}) {
		t.Fatal("all-pass should be true")
	}
	if AllPass([]Check{{OK: true}, {OK: false}}) {
		t.Fatal("all-pass should be false with a failure")
	}
}

// TestErrNoChecks verifies the sentinel.
func TestErrNoChecks(t *testing.T) {
	if ErrNoChecks.Error() != "no setup checks run" {
		t.Fatalf("ErrNoChecks = %q", ErrNoChecks.Error())
	}
}
