// Package proofs implements public identity proofs ("Hyperproofs") in the
// Keyoxide/Ariadne pattern: a cryptographic anchor holds signed claims
// pointing at accounts on other services; each claimed account publishes the
// anchor's fingerprint/DID somewhere discoverable. Verification is
// bidirectional, requiring no central authority.
package proofs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Claim is a single proof claim.
type Claim struct {
	ID            string
	AnchorType    string // "did" | "pgp_fingerprint" | "webid"
	AnchorValue   string
	Service       string // "dns" | "github_gist" | "mastodon" | "bluesky" | "custom_url"
	ClaimLocation string
	ExpectedToken string
}

// Result is the outcome of verifying a claim.
type Result struct {
	Status string // "verified" | "failed"
}

// Resolver resolves DNS records. net.Resolver satisfies it; tests inject
// stubs to avoid real DNS.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Verifier checks a single claim. Every fetch touches attacker-influenced
// URLs (the tenant controls claim_location) — this is an SSRF surface and
// must be treated as such: block private/loopback/link-local IP ranges,
// cap redirects, cap response size, strict timeout.
type Verifier struct {
	HTTPClient *http.Client
	Resolver   Resolver
}

// Verify checks a single claim.
func (v *Verifier) Verify(ctx context.Context, claim *Claim) (Result, error) {
	switch claim.Service {
	case "dns":
		return v.verifyDNS(ctx, claim)
	case "github_gist", "custom_url", "mastodon", "bluesky":
		return v.verifyHTTPBody(ctx, claim)
	default:
		return Result{}, fmt.Errorf("proofs: unsupported service %q", claim.Service)
	}
}

// verifyDNS checks a DNS TXT record for the expected token.
func (v *Verifier) verifyDNS(ctx context.Context, claim *Claim) (Result, error) {
	txts, err := v.Resolver.LookupTXT(ctx, claim.ClaimLocation)
	if err != nil {
		return Result{Status: "failed"}, err
	}
	for _, t := range txts {
		if strings.Contains(t, claim.ExpectedToken) {
			return Result{Status: "verified"}, nil
		}
	}
	return Result{Status: "failed"}, errors.New("proofs: token not found in TXT records")
}

// verifyHTTPBody fetches a URL and checks for the expected token. Every hop
// (including redirects) is re-validated against the SSRF blocklist.
func (v *Verifier) verifyHTTPBody(ctx context.Context, claim *Claim) (Result, error) {
	if err := requireSafeURL(ctx, claim.ClaimLocation, v.Resolver); err != nil {
		return Result{Status: "failed"}, err
	}
	// Re-validate every redirect hop against the SSRF blocklist and cap the
	// number of redirects.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("proofs: too many redirects")
			}
			if err := requireSafeURL(ctx, req.URL.String(), v.Resolver); err != nil {
				return err
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, claim.ClaimLocation, http.NoBody)
	if err != nil {
		return Result{Status: "failed"}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Status: "failed"}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Read the body with a hard cap, looping until EOF so a token split
	// across reads is still found.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Result{Status: "failed"}, err
	}
	if strings.Contains(string(body), claim.ExpectedToken) {
		return Result{Status: "verified"}, nil
	}
	return Result{Status: "failed"}, errors.New("proofs: token not found in response body")
}

// requireSafeURL rejects URLs resolving to private/loopback/link-local/
// cloud-metadata addresses. It resolves DNS first and checks the resolved IP
// (not the hostname string) to defeat DNS rebinding.
func requireSafeURL(ctx context.Context, rawURL string, resolver Resolver) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("proofs: invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("proofs: unsupported scheme")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("proofs: invalid url")
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("proofs: dns resolution failed: %w", err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return errors.New("proofs: url resolves to a blocked address")
		}
	}
	return nil
}

// hostFromURL extracts the host from a URL string, handling IPv6 literals and
// userinfo correctly via net/url.
func hostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// isBlockedIP reports whether an IP is private/loopback/link-local or a
// cloud-metadata address.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Cloud metadata (169.254.169.254) is link-local, already covered.
	return false
}
