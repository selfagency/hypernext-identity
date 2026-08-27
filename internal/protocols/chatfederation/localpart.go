// Package chatfederation implements the identity normalization shared by
// Matrix and XMPP federation. Hypernext acts as an upstream OIDC provider
// that Matrix's MAS and Prosody's mod_auth_oauth_external delegate to; the
// only new code is producing a username/localpart-safe claim that is valid
// as both a Matrix localpart and an RFC 7622 XMPP JID node.
package chatfederation

import (
	"fmt"
	"strings"
	"unicode"
)

// NormalizeLocalpart converts a handle/username into a form valid as both a
// Matrix localpart and an RFC 7622 JID node:
//   - lowercased
//   - disallowed characters replaced with a deterministic escape (injective,
//     so distinct inputs never collide)
//   - never empty
//
// RFC 7622 JID node rules: must not be empty, must not contain the
// disallowed set, and must not start with a space. Matrix localparts are
// more permissive but share the lowercase + safe-character requirement.
func NormalizeLocalpart(input string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(input) {
		if isAllowed(r) {
			sb.WriteRune(r)
		} else {
			// Escape disallowed runes deterministically so normalization is
			// injective ("a b" != "ab"). The escape uses only allowed chars.
			sb.WriteString(escapeRune(r))
		}
	}
	out := sb.String()
	if out == "" {
		return "user"
	}
	return out
}

// escapeRune encodes a disallowed rune as a deterministic, injective escape
// using only allowed characters. The format is "-x<hex>" where hex is the
// rune's code point; the leading '-' is unambiguous because a literal '-'
// is allowed and would be written as itself.
func escapeRune(r rune) string {
	return fmt.Sprintf("-x%x", r)
}

// isAllowed reports whether a rune is safe in both a Matrix localpart and an
// RFC 7622 JID node. We allow letters, digits, and a conservative set of
// punctuation that excludes the RFC 7622 disallowed set
// (" & ' / : < > @ and space). Everything else is dropped.
func isAllowed(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case '.', '-', '_', '~', '=', '+', '!', '$', '%', '*', '(', ')', ',', ';':
		return true
	}
	return false
}

// IsValidJIDNode reports whether a string is a valid RFC 7622 JID node.
func IsValidJIDNode(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, " ") {
		return false
	}
	for _, r := range s {
		if !isAllowed(r) {
			return false
		}
	}
	return true
}

// IsValidMatrixLocalpart reports whether a string is a valid Matrix localpart.
func IsValidMatrixLocalpart(s string) bool {
	if s == "" {
		return false
	}
	// Matrix localparts must not contain ':' (reserved for domain separator).
	if strings.Contains(s, ":") {
		return false
	}
	for _, r := range s {
		if !isAllowed(r) {
			return false
		}
	}
	return true
}
