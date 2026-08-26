package auth

import (
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// Provider wraps the zitadel/oidc OpenID Provider, exposing its HTTP handler
// for mounting behind the tenant middleware.
type Provider struct {
	*op.Provider
}

// NewProvider builds an OpenID Provider rooted at issuer (e.g.
// "https://id.example.com"). The storage must be tenant-aware; callers pass
// the tenant's store.
func NewProvider(issuer string, storage op.Storage) (*Provider, error) {
	config := &op.Config{
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       []string{"openid", "profile", "email", "offline_access"},
	}
	provider, err := op.NewProvider(config, storage, op.StaticIssuer(issuer))
	if err != nil {
		return nil, err
	}
	return &Provider{Provider: provider}, nil
}

// Handler returns the provider's HTTP handler.
func (p *Provider) Handler() http.Handler {
	return p.Provider
}
