package auth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/selfagency/sovereign/internal/store"
)

// SQLStore is a SQLite-backed implementation of op.Storage. Users, clients,
// and WebAuthn credentials are persisted in the store; auth codes and
// authorization requests are short-lived and stay in memory. Refresh tokens
// are persisted (hashed) via the store's auth_refresh_tokens table.
type SQLStore struct {
	mu       sync.RWMutex
	store    *store.Store
	authReqs map[string]*authRequest
	codes    map[string]string // code -> authRequestID
	refresh  map[string]*refreshTokenRequest
	signing  *signingKey
}

// NewSQLStore builds a SQLite-backed op.Storage. The signing key is loaded
// from the store (or generated and persisted if absent).
func NewSQLStore(ctx context.Context, st *store.Store) (*SQLStore, error) {
	priv, err := loadOrCreateSigningKey(ctx, st)
	if err != nil {
		return nil, err
	}
	return &SQLStore{
		store:    st,
		authReqs: map[string]*authRequest{},
		codes:    map[string]string{},
		refresh:  map[string]*refreshTokenRequest{},
		signing:  &signingKey{id: "signing-1", key: priv},
	}, nil
}

// loadOrCreateSigningKey loads the persisted signing key or generates one.
func loadOrCreateSigningKey(ctx context.Context, st *store.Store) (*rsa.PrivateKey, error) {
	key, err := st.GetAuthSigningKey(ctx, "signing-1")
	if err == nil {
		return parseRSAPrivateKey(key.KeyPEM)
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	priv, err := generateRSAKey()
	if err != nil {
		return nil, err
	}
	pemBytes, err := marshalRSAPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := st.SaveAuthSigningKey(ctx, store.AuthSigningKey{
		ID:        "signing-1",
		KeyPEM:    string(pemBytes),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}
	return priv, nil
}

// SigningKeyMaterial returns the raw signing key.
func (s *SQLStore) SigningKeyMaterial() *rsa.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signing.key
}

// Health reports store liveness.
func (s *SQLStore) Health(_ context.Context) error { return nil }

// --- op.AuthStorage ---

func (s *SQLStore) CreateAuthRequest(_ context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
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
	s.mu.Lock()
	s.authReqs[ar.id] = ar
	s.mu.Unlock()
	return ar, nil
}

func (s *SQLStore) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	s.mu.RLock()
	ar, ok := s.authReqs[id]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("auth request not found")
	}
	return ar, nil
}

func (s *SQLStore) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mu.RLock()
	id, ok := s.codes[code]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("auth code not found")
	}
	return s.AuthRequestByID(context.Background(), id)
}

func (s *SQLStore) SaveAuthCode(_ context.Context, id, code string) error {
	s.mu.Lock()
	s.codes[code] = id
	s.mu.Unlock()
	return nil
}

func (s *SQLStore) DeleteAuthRequest(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.authReqs, id)
	s.mu.Unlock()
	return nil
}

func (s *SQLStore) CreateAccessToken(_ context.Context, _ op.TokenRequest) (string, time.Time, error) {
	return newID(), time.Now().Add(time.Hour), nil
}

func (s *SQLStore) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, _ string) (string, string, time.Time, error) {
	access := newID()
	refresh := newID()
	// Persist the refresh token (hashed) so it survives restarts.
	clientID := ""
	if aud := request.GetAudience(); len(aud) > 0 {
		clientID = aud[0]
	}
	if err := s.store.SaveAuthRefreshToken(ctx, &store.AuthRefreshToken{
		Token:     hashToken(refresh),
		Subject:   request.GetSubject(),
		ClientID:  clientID,
		Scopes:    strings.Join(request.GetScopes(), ","),
		AuthTime:  time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return "", "", time.Time{}, err
	}
	s.mu.Lock()
	s.refresh[refresh] = &refreshTokenRequest{
		subject:  request.GetSubject(),
		clientID: clientID,
		scopes:   request.GetScopes(),
		authTime: time.Now(),
	}
	s.mu.Unlock()
	return access, refresh, time.Now().Add(time.Hour), nil
}

func (s *SQLStore) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	// Prefer the persisted (hashed) refresh token.
	subject, clientID, scopes, err := s.store.GetAuthRefreshTokenByHash(ctx, hashToken(refreshToken))
	if err == nil {
		return &refreshTokenRequest{
			subject:  subject,
			clientID: clientID,
			scopes:   scopes,
			authTime: time.Now(),
		}, nil
	}
	// Fall back to the in-memory map (for tokens minted this process).
	s.mu.RLock()
	r, ok := s.refresh[refreshToken]
	s.mu.RUnlock()
	if !ok {
		return nil, op.ErrInvalidRefreshToken
	}
	return r, nil
}

func (s *SQLStore) TerminateSession(_ context.Context, _ string, _ string) error { return nil }

func (s *SQLStore) RevokeToken(ctx context.Context, tokenOrTokenID string, _ string, _ string) *oidc.Error {
	// Revoke the persisted refresh token (by hash).
	if err := s.store.DeleteAuthRefreshToken(ctx, hashToken(tokenOrTokenID)); err != nil {
		return &oidc.Error{ErrorType: oidc.ServerError, Description: "revocation failed"}
	}
	s.mu.Lock()
	delete(s.refresh, tokenOrTokenID)
	s.mu.Unlock()
	return nil
}

func (s *SQLStore) GetRefreshTokenInfo(ctx context.Context, _ string, token string) (string, string, error) {
	subject, _, _, err := s.store.GetAuthRefreshTokenByHash(ctx, hashToken(token))
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return subject, token, nil
}

func (s *SQLStore) SigningKey(_ context.Context) (op.SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signing, nil
}

func (s *SQLStore) SignatureAlgorithms(_ context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *SQLStore) KeySet(_ context.Context) ([]op.Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return []op.Key{&key{id: s.signing.id, key: s.signing.key}}, nil
}

// --- op.OPStorage ---

func (s *SQLStore) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.store.ClientByID(ctx, clientID)
	if err != nil {
		return nil, errors.New("client not found")
	}
	return &Client{
		ID:               c.ID,
		Secret:           c.Secret,
		RedirectURIsList: c.RedirectURIs,
		Scopes:           c.Scopes,
	}, nil
}

func (s *SQLStore) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.store.ClientByID(ctx, clientID)
	if err != nil {
		return errors.New("client not found")
	}
	if c.Secret != clientSecret {
		return errors.New("invalid client secret")
	}
	return nil
}

func (s *SQLStore) SetUserinfoFromScopes(_ context.Context, _ *oidc.UserInfo, _ string, _ string, _ []string) error {
	return nil
}

func (s *SQLStore) SetUserinfoFromToken(_ context.Context, _ *oidc.UserInfo, _ string, _ string, _ string) error {
	return nil
}

func (s *SQLStore) SetIntrospectionFromToken(_ context.Context, _ *oidc.IntrospectionResponse, _ string, _ string, _ string) error {
	return nil
}

func (s *SQLStore) GetPrivateClaimsFromScopes(_ context.Context, _ string, _ string, _ []string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *SQLStore) GetKeyByIDAndClientID(_ context.Context, keyID, _ string) (*jose.JSONWebKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if keyID != s.signing.id {
		return nil, errors.New("key not found")
	}
	return &jose.JSONWebKey{Key: s.signing.key, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}, nil
}

func (s *SQLStore) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// --- helpers ---

// parseRSAPrivateKey decodes a PEM-encoded RSA private key.
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("auth: invalid PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// marshalRSAPrivateKey encodes an RSA private key as PEM.
func marshalRSAPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), nil
}

// hashToken returns the hex SHA-256 hash of a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
