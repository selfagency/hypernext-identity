// Package wellknown implements the content-negotiated profile dispatcher.
//
// A single profile URL serves three representations based on the Accept
// header: h-card (HTML), ActivityPub actor (application/activity+json), and
// DID document (application/did+json). This is the "one identity, resolved
// differently per protocol" pattern.
package wellknown

import (
	"net/http"
	"strings"
)

// Handlers holds the three content-negotiated representations.
type Handlers struct {
	// HCard serves the HTML h-card profile.
	HCard http.HandlerFunc
	// Actor serves the ActivityPub actor (application/activity+json).
	Actor http.HandlerFunc
	// DIDDoc serves the DID document (application/did+json).
	DIDDoc http.HandlerFunc
}

// ProfileHandler content-negotiates among the three representations.
func ProfileHandler(h Handlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		switch {
		case accepts(accept, "application/activity+json"):
			h.Actor(w, r)
		case accepts(accept, "application/did+json"):
			h.DIDDoc(w, r)
		default:
			h.HCard(w, r)
		}
	}
}

// accepts reports whether the Accept header prefers the given media type.
func accepts(accept, mediaType string) bool {
	if accept == "" {
		return false
	}
	// Simple substring match; a full parser is overkill for this dispatcher.
	return strings.Contains(accept, mediaType)
}
