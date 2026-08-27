package setup

import (
	"context"
	"errors"
	"net"
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

// TestNewValidator verifies the default validator is wired with real
// resolvers and https scheme.
func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", v.Scheme)
	}
	if v.HTTPClient == nil || v.LookupTXT == nil || v.LookupIP == nil {
		t.Fatal("default validator missing resolvers")
	}
}

// TestValidateWellKnownSSRF verifies the well-known check rejects a handle
// resolving to a private/loopback address (S14).
func TestValidateWellKnownSSRF(t *testing.T) {
	v := &Validator{
		HTTPClient: &http.Client{},
		LookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return []string{"did=did:plc:abc123"}, nil
		},
		Scheme: "http",
		// A resolver that reports loopback for the handle.
		LookupIP: func(_ context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	}
	checks := v.Validate(context.Background(), "127.0.0.1")
	if checks[1].OK {
		t.Fatalf("well-known check should fail for loopback handle: %+v", checks[1])
	}
}
