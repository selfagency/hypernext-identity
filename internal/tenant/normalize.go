package tenant

import (
	"net"
	"strings"
)

// NormalizeHost canonicalizes an HTTP Host header value into a tenant handle:
// it strips any port (handling bracketed IPv6 literals), lowercases the host,
// and removes a single trailing dot. A bare host is returned unchanged.
func NormalizeHost(host string) string {
	// net.SplitHostPort handles bracketed IPv6 ([::1]:8080 -> ::1) and
	// host:port (example.com:443 -> example.com). For portless hosts it
	// returns an error, in which case the input is used as-is.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	return host
}
