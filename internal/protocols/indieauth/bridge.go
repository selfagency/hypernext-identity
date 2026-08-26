// Package indieauth implements the IndieAuth bridge: it translates the
// identity-URL authorization flow onto the shared OIDC/OAuth2 core. IndieAuth
// is OAuth 2.0 profile-flavored for identity URLs, so this is a thin adapter
// over the same token issuer used by Solid-OIDC, remoteStorage, and IPFS.
package indieauth

import (
	"context"
	"errors"
	"net/http"

	"go.hacdias.com/indielib/indieauth"
)

// TokenIssuer mints tokens for an IndieAuth identity URL. The auth package
// implements this; the interface keeps the bridge decoupled and testable.
type TokenIssuer interface {
	// IssueForProfile returns an access token for the given profile URL and
	// scopes.
	IssueForProfile(ctx context.Context, profileURL string, scopes []string) (string, error)
}

// Bridge wraps the indielib IndieAuth server and delegates token minting to
// the shared OIDC core.
type Bridge struct {
	Server *indieauth.Server
	Issuer TokenIssuer
}

// NewBridge builds an IndieAuth bridge. requirePKCE enforces PKCE on
// authorization requests.
func NewBridge(requirePKCE bool, issuer TokenIssuer) *Bridge {
	return &Bridge{
		Server: indieauth.NewServer(requirePKCE, nil),
		Issuer: issuer,
	}
}

// ParseAuthorization parses and validates an IndieAuth authorization request.
func (b *Bridge) ParseAuthorization(r *http.Request) (*indieauth.AuthenticationRequest, error) {
	return b.Server.ParseAuthorization(r)
}

// ValidateTokenExchange validates a token exchange request against the
// original authorization request.
func (b *Bridge) ValidateTokenExchange(authReq *indieauth.AuthenticationRequest, r *http.Request) error {
	return b.Server.ValidateTokenExchange(authReq, r)
}

// IssueToken mints an access token for the authenticated profile URL.
func (b *Bridge) IssueToken(ctx context.Context, profileURL string, scopes []string) (string, error) {
	if profileURL == "" {
		return "", errors.New("profile URL is required")
	}
	return b.Issuer.IssueForProfile(ctx, profileURL, scopes)
}

// DiscoverApplicationMetadata fetches h-app metadata for a client ID.
func (b *Bridge) DiscoverApplicationMetadata(ctx context.Context, clientID string) (*indieauth.ApplicationMetadata, error) {
	return b.Server.DiscoverApplicationMetadata(ctx, clientID)
}
