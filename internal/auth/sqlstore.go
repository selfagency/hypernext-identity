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
	id, err := newID()
	if err != nil {
		return nil, err
	}
	ar := &authRequest{
		id:           id,
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
	id, err := newID()
	if err != nil {
		return "", time.Time{}, err
	}
	return id, time.Now().Add(time.Hour), nil
}

// refreshTokenTTL is the lifetime of a persisted refresh token. Grandfathered
// (pre-migration) tokens carry no expiry; every token minted after migration v6
// is capped at this TTL.
const refreshTokenTTL = 30 * 24 * time.Hour

func (s *SQLStore) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, refreshToken string) (string, string, time.Time, error) {
	access, err := newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	refresh, err := newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	clientID := ""
	if aud := request.GetAudience(); len(aud) > 0 {
		clientID = aud[0]
	}
	expiresAt := time.Now().UTC().Add(refreshTokenTTL)
	familyID, err := newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	now := time.Now().UTC()
	token := &store.AuthRefreshToken{
		Token:     hashToken(refresh),
		Subject:   request.GetSubject(),
		ClientID:  clientID,
		Scopes:    strings.Join(request.GetScopes(), ","),
		AuthTime:  now,
		ExpiresAt: expiresAt,
		FamilyID:  familyID,
		CreatedAt: now,
	}
	if refreshToken != "" {
		// Rotation: inherit the old token's family so reuse detection can
		// revoke the whole chain, then mark the old token rotated and insert
		// the successor atomically.
		oldHash := hashToken(refreshToken)
		if old, err := s.store.GetAuthRefreshToken(ctx, oldHash); err == nil && old.FamilyID != "" {
			token.FamilyID = old.FamilyID
		}
		if err := s.store.RotateAuthRefreshToken(ctx, oldHash, token); err != nil {
			return "", "", time.Time{}, err
		}
	} else {
		// Brand-new grant: persist with an expiry + a fresh family.
		if err := s.store.SaveAuthRefreshToken(ctx, token); err != nil {
			return "", "", time.Time{}, err
		}
	}
	s.mu.Lock()
	// The old token is spent after rotation: drop its in-memory entry so a
	// replay cannot bypass reuse detection via the map fallback.
	if refreshToken != "" {
		delete(s.refresh, refreshToken)
	}
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
	t, err := s.store.GetAuthRefreshToken(ctx, hashToken(refreshToken))
	if err == nil {
		// Revoked or expired tokens are rejected outright (never falling back
		// to the in-memory map).
		if !t.RevokedAt.IsZero() || (!t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)) {
			s.mu.Lock()
			delete(s.refresh, refreshToken)
			s.mu.Unlock()
			return nil, op.ErrInvalidRefreshToken
		}
		// Reuse detection: a rotated token must never be redeemable again.
		// Revoke the entire family (including the current successor) and drop
		// any in-memory entry for it.
		if !t.RotatedAt.IsZero() {
			_ = s.store.RevokeAuthRefreshTokenFamily(ctx, t.FamilyID)
			s.mu.Lock()
			delete(s.refresh, refreshToken)
			s.mu.Unlock()
			return nil, op.ErrInvalidRefreshToken
		}
		return &refreshTokenRequest{
			subject:  t.Subject,
			clientID: t.ClientID,
			scopes:   splitCSV(t.Scopes),
			authTime: t.AuthTime,
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

// splitCSV splits a comma-joined scope string into a slice, dropping empties.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
	// Fail closed: the sentinel and any non-argon2id stored value are rejected
	// by VerifyClientSecret, and the comparison is constant-time.
	if !store.VerifyClientSecret(clientSecret, c.Secret) {
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

// parseRSAPrivateKey decodes a PEM-encoded RSA private key. It accepts both
// PKCS#1 and PKCS#8 encodings, requires a modulus of at least 2048 bits, and
// rejects any trailing data after the PEM block.
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("auth: invalid PEM")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("auth: trailing data after PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		var pkcs8 any
		if pkcs8, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, errors.New("auth: invalid RSA private key")
		}
		rsaKey, ok := pkcs8.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("auth: not an RSA private key")
		}
		key = rsaKey
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("auth: RSA key too weak (minimum 2048 bits)")
	}
	return key, nil
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
