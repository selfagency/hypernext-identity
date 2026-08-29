package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/selfagency/sovereign/internal/store"
)

// newSQLTestStore opens a temp SQLite store.
func newSQLTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestSQLStoreClient verifies client lookup + secret auth.
func TestSQLStoreClient(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	if err := st.CreateClient(ctx, &store.Client{
		ID: "web", Secret: "s3cret", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"},
	}); err != nil {
		t.Fatal(err)
	}
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.GetClientByClientID(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if c.GetID() != "web" {
		t.Fatalf("client id = %q", c.GetID())
	}
	if err := s.AuthorizeClientIDSecret(ctx, "web", "s3cret"); err != nil {
		t.Fatalf("valid secret rejected: %v", err)
	}
	if err := s.AuthorizeClientIDSecret(ctx, "web", "wrong"); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := s.GetClientByClientID(ctx, "nope"); err == nil {
		t.Fatal("unknown client accepted")
	}
}

// TestSQLStoreSigningKey verifies the signing key is persisted and reused.
func TestSQLStoreSigningKey(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s1, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	key1 := s1.SigningKeyMaterial()

	// Reopen — the key must be the same (persisted).
	s2, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if s2.SigningKeyMaterial().N.Cmp(key1.N) != 0 {
		t.Fatal("signing key not persisted across reopen")
	}
}

// TestSQLStoreRefreshToken verifies refresh tokens persist across reopen.
func TestSQLStoreRefreshToken(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s1, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh, _, err := s1.CreateAccessAndRefreshTokens(ctx, &testTokenRequest{
		subject: "alice", audience: []string{"web"}, scopes: []string{"openid"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if access == "" || refresh == "" {
		t.Fatal("empty tokens")
	}

	// Reopen and resolve the refresh token from the persisted store.
	s2, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	req, err := s2.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatalf("refresh token not resolvable after reopen: %v", err)
	}
	if req.GetSubject() != "alice" {
		t.Fatalf("subject = %q, want alice", req.GetSubject())
	}
}

// testTokenRequest is a minimal op.TokenRequest for tests.
type testTokenRequest struct {
	subject  string
	audience []string
	scopes   []string
}

func (t *testTokenRequest) GetSubject() string                    { return t.subject }
func (t *testTokenRequest) GetAudience() []string                 { return t.audience }
func (t *testTokenRequest) GetScopes() []string                   { return t.scopes }
func (t *testTokenRequest) GetAMR() []string                      { return nil }
func (t *testTokenRequest) GetAuthTime() (time.Time, bool)        { return time.Time{}, false }
func (t *testTokenRequest) GetClientID() string                   { return t.audience[0] }
func (t *testTokenRequest) GetNonce() string                      { return "" }
func (t *testTokenRequest) GetRedirectURI() string                { return "" }
func (t *testTokenRequest) GetResponseType() oidc.ResponseType    { return oidc.ResponseTypeCode }
func (t *testTokenRequest) GetResponseMode() oidc.ResponseMode    { return oidc.ResponseModeQuery }
func (t *testTokenRequest) GetState() string                      { return "" }
func (t *testTokenRequest) GetCodeChallenge() *oidc.CodeChallenge { return nil }
func (t *testTokenRequest) Done() bool                            { return false }

// TestSQLStoreAuthRequest verifies the auth-code flow storage methods.
func TestSQLStoreAuthRequest(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}

	ar, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: "web", Scopes: []string{"openid"}, RedirectURI: "https://app.example.com/cb",
		State: "st", Nonce: "n", CodeChallenge: "challenge",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if ar.GetClientID() != "web" || ar.GetState() != "st" || ar.GetNonce() != "n" {
		t.Fatalf("auth request = %+v", ar)
	}

	// Save + resolve by code.
	if err := s.SaveAuthCode(ctx, ar.GetID(), "code123"); err != nil {
		t.Fatal(err)
	}
	byCode, err := s.AuthRequestByCode(ctx, "code123")
	if err != nil {
		t.Fatal(err)
	}
	if byCode.GetID() != ar.GetID() {
		t.Fatalf("by code = %+v", byCode)
	}
}

// TestSQLStoreAuthRequestErrors verifies unknown code/request and delete.
func TestSQLStoreAuthRequestErrors(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}

	ar, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: "web", Scopes: []string{"openid"}, RedirectURI: "https://app.example.com/cb",
		State: "st", Nonce: "n", CodeChallenge: "challenge",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	// Unknown code / request errors.
	if _, err := s.AuthRequestByCode(ctx, "nope"); err == nil {
		t.Fatal("unknown code accepted")
	}
	if _, err := s.AuthRequestByID(ctx, "nope"); err == nil {
		t.Fatal("unknown request accepted")
	}

	// Delete.
	if err := s.DeleteAuthRequest(ctx, ar.GetID()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthRequestByID(ctx, ar.GetID()); err == nil {
		t.Fatal("deleted request still resolvable")
	}
}

// TestSQLStoreKeySet verifies signing key + JWKS methods.
func TestSQLStoreKeySet(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}

	key, err := s.SigningKey(ctx)
	if err != nil || key == nil {
		t.Fatalf("signing key = %v, %v", key, err)
	}
	algs, err := s.SignatureAlgorithms(ctx)
	if err != nil || len(algs) == 0 {
		t.Fatalf("algs = %v, %v", algs, err)
	}
	keys, err := s.KeySet(ctx)
	if err != nil || len(keys) == 0 {
		t.Fatalf("keyset = %v, %v", keys, err)
	}
	jwk, err := s.GetKeyByIDAndClientID(ctx, "signing-1", "web")
	if err != nil || jwk == nil {
		t.Fatalf("jwk = %v, %v", jwk, err)
	}
	if _, err := s.GetKeyByIDAndClientID(ctx, "nope", "web"); err == nil {
		t.Fatal("unknown key accepted")
	}
}

// TestSQLStoreRevoke verifies refresh-token revocation.
func TestSQLStoreRevoke(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	_, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, &testTokenRequest{
		subject: "alice", audience: []string{"web"}, scopes: []string{"openid"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, refresh, "", ""); err != nil {
		t.Fatalf("revoke = %v", err)
	}
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Fatal("revoked refresh token still resolvable")
	}
}

// TestRefreshTokenExpiryEnforced verifies an expired refresh token is rejected on
// redemption. CreateAccessAndRefreshTokens must populate expires_at (30-day TTL)
// so that expiry is enforced; the persisted (expired) record must take precedence
// over the in-memory fallback.
func TestRefreshTokenExpiryEnforced(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	_, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, &testTokenRequest{
		subject: "alice", audience: []string{"web"}, scopes: []string{"openid"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	// Backdate the persisted expiry so the token is now expired, even though it
	// still exists in the in-memory map.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE auth_refresh_tokens SET expires_at = ? WHERE token = ?`,
		time.Now().Add(-time.Hour), hashToken(refresh)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Fatal("expired refresh token accepted")
	}
}

// TestRefreshTokenRotation verifies a redeemed refresh token is rotated: the
// client receives a fresh token and the old token can no longer be used.
func TestRefreshTokenRotation(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	_, refresh1, _, err := s.CreateAccessAndRefreshTokens(ctx, &testTokenRequest{
		subject: "alice", audience: []string{"web"}, scopes: []string{"openid"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	// Redeem refresh1; the oidc library then mints the successor token.
	req, err := s.TokenRequestByRefreshToken(ctx, refresh1)
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	_, refresh2, _, err := s.CreateAccessAndRefreshTokens(ctx, req, refresh1)
	if err != nil {
		t.Fatalf("mint successor: %v", err)
	}
	if refresh2 == refresh1 {
		t.Fatal("rotation reused the same refresh token")
	}

	// The new token is usable before the old token is replayed.
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh2); err != nil {
		t.Fatalf("new refresh token rejected: %v", err)
	}

	// Replaying the rotated (old) token must be rejected.
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh1); err == nil {
		t.Fatal("old rotated refresh token still accepted")
	}
}

// TestRefreshTokenReuseDetected verifies redeeming an already-rotated token
// (reuse) revokes the entire family, including the current successor token.
func TestRefreshTokenReuseDetected(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	_, refresh1, _, err := s.CreateAccessAndRefreshTokens(ctx, &testTokenRequest{
		subject: "alice", audience: []string{"web"}, scopes: []string{"openid"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := s.TokenRequestByRefreshToken(ctx, refresh1)
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	_, refresh2, _, err := s.CreateAccessAndRefreshTokens(ctx, req, refresh1)
	if err != nil {
		t.Fatalf("mint successor: %v", err)
	}

	// Reuse: redeeming the rotated refresh1 again must revoke the family,
	// which also invalidates the current token refresh2.
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh1); err == nil {
		t.Fatal("reused rotated refresh token accepted")
	}
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh2); err == nil {
		t.Fatal("family not revoked: successor token still accepted after reuse")
	}
}

// TestRefreshTokenReuseDetectedInMemory verifies the in-memory fallback cannot
// resurrect a rotated token. On rotation the old token's in-memory entry must be
// deleted (mirroring RevokeToken); otherwise a replay that bypasses the store
// would succeed.
func TestRefreshTokenReuseDetectedInMemory(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	_, refresh1, _, err := s.CreateAccessAndRefreshTokens(ctx, &testTokenRequest{
		subject: "alice", audience: []string{"web"}, scopes: []string{"openid"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := s.TokenRequestByRefreshToken(ctx, refresh1)
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if _, _, _, err := s.CreateAccessAndRefreshTokens(ctx, req, refresh1); err != nil {
		t.Fatalf("mint successor: %v", err)
	}

	// Force the in-memory path: drop the persisted row so the fallback map is
	// the only place the old token could survive. On rotation its map entry
	// must already be gone, so the replay is rejected.
	if _, err := st.DB().ExecContext(ctx,
		`DELETE FROM auth_refresh_tokens WHERE token = ?`, hashToken(refresh1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh1); err == nil {
		t.Fatal("rotated refresh token resurrected via in-memory fallback")
	}
}

// TestSQLStoreHealth verifies Health is a no-op success.
func TestSQLStoreHealth(t *testing.T) {
	st := newSQLTestStore(t)
	s, err := NewSQLStore(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background()); err != nil {
		t.Fatalf("health = %v", err)
	}
}

// TestSQLStoreNoopMethods verifies the op.Storage no-op interface methods
// return without error.
func TestSQLStoreNoopMethods(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}

	// CreateAccessToken returns a non-empty token + future expiry.
	tok, exp, err := s.CreateAccessToken(ctx, &testTokenRequest{subject: "alice", audience: []string{"web"}, scopes: []string{"openid"}})
	if err != nil || tok == "" || exp.IsZero() {
		t.Fatalf("CreateAccessToken = %q %v %v", tok, exp, err)
	}

	// TerminateSession is a no-op.
	if err := s.TerminateSession(ctx, "alice", "web"); err != nil {
		t.Fatalf("TerminateSession = %v", err)
	}

	// GetRefreshTokenInfo for an unknown token -> ErrInvalidRefreshToken.
	if _, _, err := s.GetRefreshTokenInfo(ctx, "web", "nope"); err == nil {
		t.Fatal("GetRefreshTokenInfo unknown token accepted")
	}
}

// TestSQLStoreUserinfoNoops verifies the userinfo/introspection/claims no-op
// methods return without error.
func TestSQLStoreUserinfoNoops(t *testing.T) {
	ctx := context.Background()
	st := newSQLTestStore(t)
	s, err := NewSQLStore(ctx, st)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetUserinfoFromScopes(ctx, &oidc.UserInfo{}, "alice", "web", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfoFromScopes = %v", err)
	}
	if err := s.SetUserinfoFromToken(ctx, &oidc.UserInfo{}, "alice", "web", "tok"); err != nil {
		t.Fatalf("SetUserinfoFromToken = %v", err)
	}
	if err := s.SetIntrospectionFromToken(ctx, &oidc.IntrospectionResponse{}, "alice", "web", "tok"); err != nil {
		t.Fatalf("SetIntrospectionFromToken = %v", err)
	}
	claims, err := s.GetPrivateClaimsFromScopes(ctx, "alice", "web", []string{"openid"})
	if err != nil || claims == nil {
		t.Fatalf("GetPrivateClaimsFromScopes = %v, %v", claims, err)
	}
	scopes, err := s.ValidateJWTProfileScopes(ctx, "alice", []string{"openid"})
	if err != nil || len(scopes) != 1 {
		t.Fatalf("ValidateJWTProfileScopes = %v, %v", scopes, err)
	}
}

// TestParseRSAPrivateKeyPKCS8 verifies a PKCS#8-encoded RSA private key is
// accepted in addition to PKCS#1.
func TestParseRSAPrivateKeyPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	got, err := parseRSAPrivateKey(pemStr)
	if err != nil {
		t.Fatalf("parseRSAPrivateKey(PKCS#8): %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Fatal("parsed key modulus mismatch")
	}
}

// TestParseRSAPrivateKeyRejectsWeak verifies keys with a modulus below 2048
// bits are rejected.
func TestParseRSAPrivateKeyRejectsWeak(t *testing.T) {
	// #nosec G402 -- negative test: verifies the parser rejects a <2048-bit key.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	if _, err := parseRSAPrivateKey(pemStr); err == nil {
		t.Fatal("weak (<2048-bit) key accepted")
	}
}

// TestParseRSAPrivateKeyRejectsTrailing verifies data after the PEM block is
// rejected.
func TestParseRSAPrivateKeyRejectsTrailing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})) + "\ntrailing garbage\n"
	if _, err := parseRSAPrivateKey(pemStr); err == nil {
		t.Fatal("trailing data after PEM block accepted")
	}
}

// TestNewIDPropagatesError verifies newID returns the rand.Read error instead
// of silently discarding it.
func TestNewIDPropagatesError(t *testing.T) {
	orig := rand.Reader
	rand.Reader = errorReader{}
	t.Cleanup(func() { rand.Reader = orig })

	if _, err := newID(); err == nil {
		t.Fatal("newID did not propagate rand.Read error")
	}
}

// errorReader is an io.Reader that always fails, used to inject rand.Read
// failures.
type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("injected rand failure") }
