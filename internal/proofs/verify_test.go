package proofs

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeResolver resolves hosts to fixed IPs.
type fakeResolver struct {
	ips map[string][]net.IPAddr
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, errors.New("no txt")
}

// TestVerifyDNS verifies DNS TXT token presence/absence.
func TestVerifyDNS(t *testing.T) {
	// Test the verifyDNS logic directly with a stub resolver.
	vr := &Verifier{Resolver: &stubTXTResolver{txts: map[string][]string{
		"_atproto.alice.example.com": {"did=did:plc:abc123"},
	}}}
	res, err := vr.Verify(context.Background(), &Claim{
		Service:       "dns",
		ClaimLocation: "_atproto.alice.example.com",
		ExpectedToken: "did:plc:abc123",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "verified" {
		t.Fatalf("status = %s, want verified", res.Status)
	}

	// Token absent.
	vr2 := &Verifier{Resolver: &stubTXTResolver{txts: map[string][]string{"x.example.com": {"v=spf1"}}}}
	res2, _ := vr2.Verify(context.Background(), &Claim{
		Service:       "dns",
		ClaimLocation: "x.example.com",
		ExpectedToken: "did:plc:abc123",
	})
	if res2.Status != "failed" {
		t.Fatalf("status = %s, want failed", res2.Status)
	}
}

// stubTXTResolver resolves TXT records.
type stubTXTResolver struct {
	txts map[string][]string
}

func (s *stubTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txts, ok := s.txts[name]; ok {
		return txts, nil
	}
	return nil, errors.New("no such host")
}

func (s *stubTXTResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return nil, errors.New("no ip")
}

// TestVerifyHTTPBody verifies HTTP body token presence.
func TestVerifyHTTPBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proof@ariadne.id=abc123"))
	}))
	defer srv.Close()

	// The SSRF check resolves the host; return a public IP so the check
	// passes (the actual request still goes to the loopback test server).
	host := hostFromURL(srv.URL)
	v := &Verifier{
		HTTPClient: srv.Client(),
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			host: {{IP: net.ParseIP("93.184.216.34")}},
		}},
	}
	res, err := v.Verify(context.Background(), &Claim{
		Service:       "custom_url",
		ClaimLocation: srv.URL,
		ExpectedToken: "abc123",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "verified" {
		t.Fatalf("status = %s, want verified", res.Status)
	}
}

// TestVerifyUnsupportedService verifies an unsupported service errors.
func TestVerifyUnsupportedService(t *testing.T) {
	v := &Verifier{}
	if _, err := v.Verify(context.Background(), &Claim{Service: "xmpp"}); err == nil {
		t.Fatal("expected error for unsupported service")
	}
}

// TestRequireSafeURLPrivateIP verifies private IPs are blocked (release gate).
func TestRequireSafeURLPrivateIP(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"10.0.0.1": {{IP: net.ParseIP("10.0.0.1")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://10.0.0.1/", v.Resolver); err == nil {
		t.Fatal("expected error for private IP")
	}
}

// TestRequireSafeURLLoopback verifies loopback is rejected.
func TestRequireSafeURLLoopback(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"127.0.0.1": {{IP: net.ParseIP("127.0.0.1")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://127.0.0.1/", v.Resolver); err == nil {
		t.Fatal("expected error for loopback")
	}
}

// TestRequireSafeURLPublicIP verifies public IPs are allowed.
func TestRequireSafeURLPublicIP(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"example.com": {{IP: net.ParseIP("93.184.216.34")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://example.com/", v.Resolver); err != nil {
		t.Fatalf("public IP rejected: %v", err)
	}
}

// TestRequireSafeURLDNSRebind verifies a host resolving to a private IP is
// rejected even if the hostname looks public (DNS rebinding defense).
func TestRequireSafeURLDNSRebind(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"public.example.com": {{IP: net.ParseIP("169.254.169.254")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://public.example.com/", v.Resolver); err == nil {
		t.Fatal("expected error for DNS-rebind to metadata IP")
	}
}

// TestHostFromURL verifies host extraction.
func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"http://example.com/path":  "example.com",
		"https://example.com:8443": "example.com",
		"http://10.0.0.1/":         "10.0.0.1",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Fatalf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHostFromURLIPv6 verifies IPv6 literals and userinfo are parsed
// correctly (S13). net/url.Hostname returns IPv6 without brackets.
func TestHostFromURLIPv6(t *testing.T) {
	cases := map[string]string{
		"http://[::1]/":              "::1",
		"http://[2001:db8::1]:8080/": "2001:db8::1",
		"http://user@127.0.0.1/":     "127.0.0.1",
		"http://user@example.com/":   "example.com",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Fatalf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRequireSafeURLRejectsNonHTTP verifies non-http(s) schemes are rejected
// (S13).
func TestRequireSafeURLRejectsNonHTTP(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"example.com": {{IP: net.ParseIP("93.184.216.34")}},
	}}}
	for _, u := range []string{"file:///etc/passwd", "gopher://example.com/", "ftp://example.com/"} {
		if err := requireSafeURL(context.Background(), u, v.Resolver); err == nil {
			t.Fatalf("requireSafeURL(%q) succeeded, want error", u)
		}
	}
}

// TestVerifyHTTPBodyRedirectRevalidated verifies a redirect to a private IP
// is rejected (S8). The initial URL resolves to a public IP, but the redirect
// target resolves to loopback — the client must re-validate each hop.
func TestVerifyHTTPBodyRedirectRevalidated(t *testing.T) {
	// The redirect target is a loopback server.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proof@ariadne.id=abc123"))
	}))
	defer target.Close()

	// The initial URL redirects to the loopback target.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// Both hosts resolve to public IPs in the resolver, but the redirect
	// target is actually loopback. The client must re-validate the redirect
	// hop and reject it.
	v := &Verifier{
		HTTPClient: redirector.Client(),
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			hostFromURL(redirector.URL): {{IP: net.ParseIP("93.184.216.34")}},
			hostFromURL(target.URL):     {{IP: net.ParseIP("127.0.0.1")}},
		}},
	}
	res, err := v.Verify(context.Background(), &Claim{
		Service:       "custom_url",
		ClaimLocation: redirector.URL,
		ExpectedToken: "abc123",
	})
	if err == nil {
		t.Fatalf("redirect to loopback not rejected (status %s)", res.Status)
	}
}

// TestVerifyHTTPBodySplitToken verifies a token split across two reads is
// still found (S8). The current single Read may return short.
func TestVerifyHTTPBodySplitToken(t *testing.T) {
	// A server that writes the token in two chunks with a flush between.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proof@ariadne.id=abc"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		w.Write([]byte("123"))
	}))
	defer srv.Close()

	host := hostFromURL(srv.URL)
	v := &Verifier{
		HTTPClient: srv.Client(),
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			host: {{IP: net.ParseIP("93.184.216.34")}},
		}},
	}
	res, err := v.Verify(context.Background(), &Claim{
		Service:       "custom_url",
		ClaimLocation: srv.URL,
		ExpectedToken: "abc123",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "verified" {
		t.Fatalf("status = %s, want verified (split token missed)", res.Status)
	}
}

// TestVerifyHTTPBodyTooManyRedirects verifies the redirect cap is enforced
// (S8).
func TestVerifyHTTPBodyTooManyRedirects(t *testing.T) {
	// A server that redirects to itself forever.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer srv.Close()

	host := hostFromURL(srv.URL)
	v := &Verifier{
		HTTPClient: srv.Client(),
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			host: {{IP: net.ParseIP("93.184.216.34")}},
		}},
	}
	res, err := v.Verify(context.Background(), &Claim{
		Service:       "custom_url",
		ClaimLocation: srv.URL,
		ExpectedToken: "abc123",
	})
	if err == nil {
		t.Fatalf("expected error for too many redirects (status %s)", res.Status)
	}
}

// TestVerifyHTTPBodyFetchError verifies a fetch error (e.g. connection
// refused) is surfaced (S8).
func TestVerifyHTTPBodyFetchError(t *testing.T) {
	// A closed server -> connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	host := hostFromURL(url)
	v := &Verifier{
		HTTPClient: &http.Client{},
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			host: {{IP: net.ParseIP("93.184.216.34")}},
		}},
	}
	res, err := v.Verify(context.Background(), &Claim{
		Service:       "custom_url",
		ClaimLocation: url,
		ExpectedToken: "abc123",
	})
	if err == nil {
		t.Fatalf("expected fetch error (status %s)", res.Status)
	}
}

// TestIsBlockedIP verifies IP classification.
func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "fe80::1"}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("isBlockedIP(%s) = false, want true", s)
		}
	}
	if isBlockedIP(net.ParseIP("93.184.216.34")) {
		t.Fatal("public IP should not be blocked")
	}
}
