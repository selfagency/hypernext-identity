package solid

import (
	"fmt"
	"net/http"
)

// WebIDConfig holds the URLs referenced by a WebID profile.
type WebIDConfig struct {
	// Handle is the tenant handle (e.g. alice.example.com).
	Handle string
	// IdentityHost is the OIDC issuer host (e.g. id.example.com).
	IdentityHost string
	// StorageRoot is the pod storage root URL.
	StorageRoot string
}

// ServeWebID serves a WebID profile document as Turtle.
func ServeWebID(cfg WebIDConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		_, _ = fmt.Fprintf(w, `@prefix solid: <http://www.w3.org/ns/solid/terms#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.

<https://%s/profile#me>
    a foaf:Person ;
    solid:oidcIssuer <https://%s> ;
    solid:storage <%s> .
`, cfg.Handle, cfg.IdentityHost, cfg.StorageRoot)
	}
}
