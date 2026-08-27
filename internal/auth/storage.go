// Package auth implements the unified OIDC/OAuth2 provider core (via
// zitadel/oidc) plus WebAuthn passkeys (via go-webauthn). Every downstream
// protocol (Solid-OIDC, IndieAuth, remoteStorage bearer tokens, IPFS pinning)
// gates on tokens issued by this core.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// User is a tenant identity that can authenticate via OIDC and hold
// WebAuthn credentials.
type User struct {
	ID          string
	Handle      string // e.g. "alice.example.com"
	DisplayName string
	// Credentials holds WebAuthn passkeys (populated in the WebAuthn phase).
	Credentials []webauthnCredential
}

// webauthnCredential is a placeholder to keep the storage self-contained;
// the WebAuthn phase replaces it with go-webauthn's Credential type.
type webauthnCredential struct {
	ID []byte
}

// Client is an OIDC relying party registered with the provider.
type Client struct {
	ID               string
	Secret           string
	RedirectURIsList []string
	Scopes           []string
}

// signingKey wraps an RSA key for ID/access token signing.
type signingKey struct {
	id  string
	key any
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *signingKey) Key() any                                    { return k.key }
func (k *signingKey) ID() string                                  { return k.id }

// key is the public half exposed in the JWKS.
type key struct {
	id  string
	key any
}

func (k *key) ID() string                         { return k.id }
func (k *key) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *key) Use() string                        { return "sig" }
func (k *key) Key() any                           { return k.key }

// authRequest is the stored authorization request (auth code flow).
type authRequest struct {
	id            string
	clientID      string
	scopes        []string
	redirectURI   string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	state         string
	nonce         string
	codeChallenge *oidc.CodeChallenge
	subject       string
	authTime      time.Time
	done          bool
}

func (a *authRequest) GetID() string                         { return a.id }
func (a *authRequest) GetACR() string                        { return "" }
func (a *authRequest) GetAMR() []string                      { return nil }
func (a *authRequest) GetAudience() []string                 { return []string{a.clientID} }
func (a *authRequest) GetAuthTime() time.Time                { return a.authTime }
func (a *authRequest) GetClientID() string                   { return a.clientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.codeChallenge }
func (a *authRequest) GetNonce() string                      { return a.nonce }
func (a *authRequest) GetRedirectURI() string                { return a.redirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType    { return a.responseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode    { return a.responseMode }
func (a *authRequest) GetScopes() []string                   { return a.scopes }
func (a *authRequest) GetState() string                      { return a.state }
func (a *authRequest) GetSubject() string                    { return a.subject }
func (a *authRequest) Done() bool                            { return a.done }

// refreshTokenRequest is the stored refresh token grant.
type refreshTokenRequest struct {
	subject  string
	clientID string
	scopes   []string
	amr      []string
	authTime time.Time
}

func (r *refreshTokenRequest) GetAMR() []string                 { return r.amr }
func (r *refreshTokenRequest) GetAudience() []string            { return []string{r.clientID} }
func (r *refreshTokenRequest) GetAuthTime() time.Time           { return r.authTime }
func (r *refreshTokenRequest) GetClientID() string              { return r.clientID }
func (r *refreshTokenRequest) GetScopes() []string              { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string               { return r.subject }
func (r *refreshTokenRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }

// MemoryStore is an in-memory implementation of op.Storage. It is the
// TDD-friendly default; a SQLite-backed store replaces it in a later phase.
type MemoryStore struct {
	users    map[string]*User
	clients  map[string]*Client
	authReqs map[string]*authRequest
	codes    map[string]string // code -> authRequestID
	refresh  map[string]*refreshTokenRequest
	signing  *signingKey
}

// NewMemoryStore builds a store with a generated signing key.
func NewMemoryStore() (*MemoryStore, error) {
	priv, err := generateRSAKey()
	if err != nil {
		return nil, err
	}
	return &MemoryStore{
		users:    map[string]*User{},
		clients:  map[string]*Client{},
		authReqs: map[string]*authRequest{},
		codes:    map[string]string{},
		refresh:  map[string]*refreshTokenRequest{},
		signing:  &signingKey{id: "signing-1", key: priv},
	}, nil
}

// AddUser registers a user.
func (s *MemoryStore) AddUser(u *User) { s.users[u.ID] = u }

// SetSigningKey replaces the signing key (used to restore a persisted key).
func (s *MemoryStore) SetSigningKey(priv any) {
	s.signing = &signingKey{id: "signing-1", key: priv}
}

// SigningKeyMaterial returns the raw signing key material.
func (s *MemoryStore) SigningKeyMaterial() any {
	return s.signing.key
}

// AddClient registers an OIDC client.
func (s *MemoryStore) AddClient(c *Client) { s.clients[c.ID] = c }

// UserByID returns a user by ID.
func (s *MemoryStore) UserByID(id string) (*User, bool) {
	u, ok := s.users[id]
	return u, ok
}

// Health reports store liveness.
func (s *MemoryStore) Health(_ context.Context) error { return nil }

// --- op.AuthStorage ---

func (s *MemoryStore) CreateAuthRequest(_ context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	ar := &authRequest{
		id:           newID(),
		clientID:     req.ClientID,
		scopes:       req.Scopes,
		redirectURI:  req.RedirectURI,
		responseType: req.ResponseType,
		responseMode: req.ResponseMode,
		state:        req.State,
		nonce:        req.Nonce,
		codeChallenge: &oidc.CodeChallenge{
			Challenge: req.CodeChallenge,
			Method:    oidc.CodeChallengeMethodS256,
		},
		authTime: time.Now(),
	}
	s.authReqs[ar.id] = ar
	return ar, nil
}

func (s *MemoryStore) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	ar, ok := s.authReqs[id]
	if !ok {
		return nil, errors.New("auth request not found")
	}
	return ar, nil
}

func (s *MemoryStore) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	id, ok := s.codes[code]
	if !ok {
		return nil, errors.New("auth code not found")
	}
	return s.AuthRequestByID(context.Background(), id)
}

func (s *MemoryStore) SaveAuthCode(_ context.Context, id, code string) error {
	s.codes[code] = id
	return nil
}

func (s *MemoryStore) DeleteAuthRequest(_ context.Context, id string) error {
	delete(s.authReqs, id)
	return nil
}

func (s *MemoryStore) CreateAccessToken(_ context.Context, _ op.TokenRequest) (string, time.Time, error) {
	return newID(), time.Now().Add(time.Hour), nil
}

func (s *MemoryStore) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, _ string) (string, string, time.Time, error) {
	access := newID()
	refresh := newID()
	// Persist the refresh token so TokenRequestByRefreshToken can resolve it.
	s.refresh[refresh] = &refreshTokenRequest{
		subject:  request.GetSubject(),
		clientID: request.GetAudience()[0],
		scopes:   request.GetScopes(),
		authTime: time.Now(),
	}
	return access, refresh, time.Now().Add(time.Hour), nil
}

func (s *MemoryStore) TokenRequestByRefreshToken(_ context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	r, ok := s.refresh[refreshToken]
	if !ok {
		return nil, op.ErrInvalidRefreshToken
	}
	return r, nil
}

func (s *MemoryStore) TerminateSession(_ context.Context, _ string, _ string) error { return nil }

func (s *MemoryStore) RevokeToken(_ context.Context, tokenOrTokenID string, _ string, _ string) *oidc.Error {
	delete(s.refresh, tokenOrTokenID)
	return nil
}

func (s *MemoryStore) GetRefreshTokenInfo(_ context.Context, _ string, token string) (string, string, error) {
	r, ok := s.refresh[token]
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}
	return r.subject, token, nil
}

func (s *MemoryStore) SigningKey(_ context.Context) (op.SigningKey, error) {
	return s.signing, nil
}

func (s *MemoryStore) SignatureAlgorithms(_ context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *MemoryStore) KeySet(_ context.Context) ([]op.Key, error) {
	return []op.Key{&key{id: s.signing.id, key: s.signing.key}}, nil
}

// --- op.OPStorage ---

func (s *MemoryStore) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	c, ok := s.clients[clientID]
	if !ok {
		return nil, errors.New("client not found")
	}
	return c, nil
}

func (s *MemoryStore) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	c, ok := s.clients[clientID]
	if !ok {
		return errors.New("client not found")
	}
	if c.Secret != clientSecret {
		return errors.New("invalid client secret")
	}
	return nil
}

func (s *MemoryStore) SetUserinfoFromScopes(_ context.Context, _ *oidc.UserInfo, _ string, _ string, _ []string) error {
	return nil
}

func (s *MemoryStore) SetUserinfoFromToken(_ context.Context, _ *oidc.UserInfo, _ string, _ string, _ string) error {
	return nil
}

func (s *MemoryStore) SetIntrospectionFromToken(_ context.Context, _ *oidc.IntrospectionResponse, _ string, _ string, _ string) error {
	return nil
}

func (s *MemoryStore) GetPrivateClaimsFromScopes(_ context.Context, _ string, _ string, _ []string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *MemoryStore) GetKeyByIDAndClientID(_ context.Context, keyID, _ string) (*jose.JSONWebKey, error) {
	if keyID != s.signing.id {
		return nil, errors.New("key not found")
	}
	return &jose.JSONWebKey{Key: s.signing.key, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}, nil
}

func (s *MemoryStore) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// --- Client implements op.Client ---

func (c *Client) GetID() string                       { return c.ID }
func (c *Client) RedirectURIs() []string              { return c.RedirectURIsList }
func (c *Client) PostLogoutRedirectURIs() []string    { return nil }
func (c *Client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c *Client) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (c *Client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *Client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c *Client) LoginURL(_ string) string            { return "" }
func (c *Client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }

func (c *Client) IDTokenLifetime() time.Duration { return time.Hour }

func (c *Client) DevMode() bool                                                       { return false }
func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string     { return nil }
func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string { return nil }
func (c *Client) IsScopeAllowed(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *Client) ClockSkew() time.Duration             { return 0 }

// --- helpers ---

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateRSAKey creates an RSA-2048 signing key for ID/access tokens.
func generateRSAKey() (any, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
