package auth

import (
	"context"
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

	// Userinfo/introspection/claims no-ops.
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
