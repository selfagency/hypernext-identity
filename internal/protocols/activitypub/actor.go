// Package activitypub implements the identity-only slice of ActivityPub:
// a minimal actor document and HTTP Message Signature verification. Full
// inbox/outbox delivery lives in the content server.
package activitypub

import (
	"encoding/json"
	"net/http"

	"github.com/selfagency/sovereign/internal/tenant"
)

// Actor is a minimal ActivityPub Person actor document.
type Actor struct {
	Context           string `json:"@context"`
	ID                string `json:"id"`
	Type              string `json:"type"`
	PreferredUsername string `json:"preferredUsername"`
	Inbox             string `json:"inbox"`
	Outbox            string `json:"outbox"`
	URL               string `json:"url"`
	PublicKey         PubKey `json:"publicKey"`
}

// PubKey is the actor's public key for signature verification.
type PubKey struct {
	ID           string `json:"id"`
	Owner        string `json:"owner"`
	PublicKeyPem string `json:"publicKeyPem"`
}

// ActorConfig holds the URLs for an actor document.
type ActorConfig struct {
	// Handle is the tenant handle (e.g. alice.example.com).
	Handle string
	// PublicKeyPEM is the actor's RSA public key in PEM format.
	PublicKeyPEM string
}

// ServeActor serves the ActivityPub actor document for the tenant in context.
func ServeActor(cfg ActorConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, ok := tenant.FromContext(r.Context())
		if !ok {
			http.NotFound(w, r)
			return
		}
		base := "https://" + t.Handle
		actor := Actor{
			Context:           "https://www.w3.org/ns/activitystreams",
			ID:                base + "/actor",
			Type:              "Person",
			PreferredUsername: t.Handle,
			Inbox:             base + "/actor/inbox",
			Outbox:            base + "/actor/outbox",
			URL:               base + "/",
			PublicKey: PubKey{
				ID:           base + "/actor#main-key",
				Owner:        base + "/actor",
				PublicKeyPem: cfg.PublicKeyPEM,
			},
		}
		w.Header().Set("Content-Type", "application/activity+json")
		if err := json.NewEncoder(w).Encode(actor); err != nil {
			http.Error(w, "encoding error", http.StatusInternalServerError)
		}
	}
}
