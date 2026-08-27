// Package auth access-token support: short-lived signed JWTs used as bearer
// credentials at resource endpoints (remoteStorage, Solid). Refresh tokens are
// long-lived and are accepted ONLY at the OIDC token endpoint — never here.
package auth

import (
	"crypto/rsa"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// AccessTokenTTL is the default lifetime of a signed access token.
const AccessTokenTTL = 15 * time.Minute

// AccessToken is the claim set carried by a signed resource-access token.
type AccessToken struct {
	Subject  string   `json:"sub"`
	Scopes   []string `json:"scp"`
	Issuer   string   `json:"iss,omitempty"`
	Audience string   `json:"aud,omitempty"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	ID       string   `json:"jti"`
}

// MintAccessToken signs a short-lived access token for subject with the given
// scopes using the RSA signing key.
func MintAccessToken(priv *rsa.PrivateKey, subject string, scopes []string, ttl time.Duration) (string, error) {
	if priv == nil {
		return "", errors.New("auth: nil signing key")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := AccessToken{
		Subject:  subject,
		Scopes:   scopes,
		Expiry:   now.Add(ttl).Unix(),
		IssuedAt: now.Unix(),
		ID:       newID(),
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// ValidateAccessToken verifies the signature and expiry of an access token and
// returns its claims. It rejects expired tokens and tokens signed by a
// different key.
func ValidateAccessToken(priv *rsa.PrivateKey, token string) (*AccessToken, error) {
	if priv == nil {
		return nil, errors.New("auth: nil signing key")
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, errors.New("auth: invalid access token")
	}
	var claims AccessToken
	if err := parsed.Claims(priv.Public(), &claims); err != nil {
		return nil, errors.New("auth: invalid access token signature")
	}
	if claims.Expiry != 0 && time.Now().After(time.Unix(claims.Expiry, 0)) {
		return nil, errors.New("auth: access token expired")
	}
	return &claims, nil
}
