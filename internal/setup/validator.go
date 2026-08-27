// Package setup implements the first-run setup wizard. It validates that a
// tenant's DNS and well-known endpoints are correctly configured before the
// operator finishes provisioning, so non-technical users can spin up a server
// without guessing at DNS records.
package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Check is a single setup validation result.
type Check struct {
	// Name is the check name (e.g. "DNS TXT", "well-known").
	Name string
	// OK reports whether the check passed.
	OK bool
	// Detail is a human-readable message.
	Detail string
}

// Validator performs setup checks against a live host.
type Validator struct {
	// HTTPClient is used for well-known fetches.
	HTTPClient *http.Client
	// LookupTXT resolves DNS TXT records (net.DefaultResolver in prod).
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// LookupIP resolves a host to IPs (net.DefaultResolver in prod). Used to
	// block SSRF to private/loopback addresses.
	LookupIP func(ctx context.Context, host string) ([]net.IPAddr, error)
	// Scheme is the well-known URL scheme (default https).
	Scheme string
}

// NewValidator builds a validator with default resolvers.
func NewValidator() *Validator {
	return &Validator{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		LookupTXT:  net.DefaultResolver.LookupTXT,
		LookupIP:   net.DefaultResolver.LookupIPAddr,
		Scheme:     "https",
	}
}

// Validate runs all setup checks for a handle.
func (v *Validator) Validate(ctx context.Context, handle string) []Check {
	return []Check{
		v.checkDNSTXT(ctx, handle),
		v.checkWellKnown(ctx, handle),
	}
}

// checkDNSTXT verifies the _atproto DNS TXT record exists.
func (v *Validator) checkDNSTXT(ctx context.Context, handle string) Check {
	name := "_atproto." + handle
	records, err := v.LookupTXT(ctx, name)
	if err != nil {
		return Check{Name: "DNS TXT", OK: false, Detail: fmt.Sprintf("no _atproto TXT record: %v", err)}
	}
	for _, r := range records {
		if strings.HasPrefix(r, "did=") {
			return Check{Name: "DNS TXT", OK: true, Detail: "found _atproto TXT record"}
		}
	}
	return Check{Name: "DNS TXT", OK: false, Detail: "_atproto TXT record missing did= value"}
}

// checkWellKnown verifies the /.well-known/atproto-did endpoint responds. It
// rejects handles resolving to private/loopback addresses (SSRF guard, S14).
func (v *Validator) checkWellKnown(ctx context.Context, handle string) Check {
	scheme := v.Scheme
	if scheme == "" {
		scheme = "https"
	}
	// SSRF guard: reject handles resolving to private/loopback addresses.
	if v.LookupIP != nil {
		ips, err := v.LookupIP(ctx, handle)
		if err != nil {
			return Check{Name: "well-known", OK: false, Detail: fmt.Sprintf("dns resolution failed: %v", err)}
		}
		for _, ip := range ips {
			if isBlockedIP(ip.IP) {
				return Check{Name: "well-known", OK: false, Detail: "handle resolves to a blocked address"}
			}
		}
	}
	url := scheme + "://" + handle + "/.well-known/atproto-did"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return Check{Name: "well-known", OK: false, Detail: err.Error()}
	}
	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return Check{Name: "well-known", OK: false, Detail: fmt.Sprintf("fetch failed: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Check{Name: "well-known", OK: false, Detail: fmt.Sprintf("status %d", resp.StatusCode)}
	}
	return Check{Name: "well-known", OK: true, Detail: "well-known endpoint responds"}
}

// isBlockedIP reports whether an IP is private/loopback/link-local or a
// cloud-metadata address.
func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// AllPass reports whether every check passed.
func AllPass(checks []Check) bool {
	for _, c := range checks {
		if !c.OK {
			return false
		}
	}
	return true
}

// ErrNoChecks is returned when no checks were run.
var ErrNoChecks = errors.New("no setup checks run")
