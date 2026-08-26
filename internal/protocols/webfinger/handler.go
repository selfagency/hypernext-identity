// Package webfinger implements RFC 7033 WebFinger discovery.
//
// It is the connective tissue of the identity server: one identity, one
// set of .well-known endpoints, resolved differently per protocol. A single
// WebFinger response carries links for remoteStorage, ActivityPub, the OIDC
// issuer, and atproto handle resolution.
package webfinger

import (
	"encoding/json"
	"net/http"

	"github.com/hypernext/identity/internal/tenant"
)

// Link is a single WebFinger link relation (RFC 7033 §4.4.4).
type Link struct {
	Rel  string `json:"rel"`
	Type string `json:"type,omitempty"`
	Href string `json:"href,omitempty"`
}

// JRD is a JSON Resource Descriptor (RFC 7033 §4.4).
type JRD struct {
	Subject string   `json:"subject"`
	Aliases []string `json:"aliases,omitempty"`
	Links   []Link   `json:"links"`
}

// Config holds the per-tenant URLs that WebFinger links point to.
type Config struct {
	// IdentityHost is the OIDC issuer / identity server host (e.g. id.example.com).
	IdentityHost string
	// StorageRoot is the remoteStorage root URL.
	StorageRoot string
	// ActorURL is the ActivityPub actor URL.
	ActorURL string
}

// Handler serves RFC 7033 WebFinger for the tenant in the request context.
// It requires the ?resource= query parameter.
func Handler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, ok := tenant.FromContext(r.Context())
		if !ok {
			http.NotFound(w, r)
			return
		}
		resource := r.URL.Query().Get("resource")
		if resource == "" {
			http.Error(w, "missing resource parameter", http.StatusBadRequest)
			return
		}

		jrd := JRD{
			Subject: resource,
			Links: []Link{
				// remoteStorage discovery (draft-dejong-remotestorage).
				{Rel: "http://tools.ietf.org/id/draft-dejong-remotestorage", Href: cfg.StorageRoot},
				// ActivityPub actor discovery.
				{Rel: "self", Type: "application/activity+json", Href: cfg.ActorURL},
				// OIDC issuer discovery.
				{Rel: "http://openid.net/specs/connect/1.0/issuer", Href: "https://" + cfg.IdentityHost},
			},
		}
		// The tenant handle is an alias of the resource.
		jrd.Aliases = []string{"https://" + t.Handle}

		w.Header().Set("Content-Type", "application/jrd+json")
		if err := json.NewEncoder(w).Encode(jrd); err != nil {
			http.Error(w, "encoding error", http.StatusInternalServerError)
		}
	}
}
