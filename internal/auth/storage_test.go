package auth

import (
	"context"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TestMemoryStoreUserAndClient verifies user/client registration and lookup.
func TestMemoryStoreUserAndClient(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	store.AddUser(&User{ID: "u1", Handle: "a.example.com"})
	if u, ok := store.UserByID("u1"); !ok || u.Handle != "a.example.com" {
		t.Fatalf("UserByID(u1) = %+v, %v; want handle a.example.com", u, ok)
	}
	if _, ok := store.UserByID("missing"); ok {
		t.Fatal("expected missing user")
	}

	store.AddClient(&Client{ID: "c1", Secret: "s1", RedirectURIsList: []string{"https://x/cb"}, Scopes: []string{"openid"}})
	c, err := store.GetClientByClientID(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if c.GetID() != "c1" {
		t.Fatalf("client id = %s, want c1", c.GetID())
	}
	if _, err := store.GetClientByClientID(ctx, "missing"); err == nil {
		t.Fatal("expected error for missing client")
	}
}

// TestAuthorizeClientIDSecret verifies client secret auth.
func TestAuthorizeClientIDSecret(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store.AddClient(&Client{ID: "c1", Secret: "secret-1"})

	if err := store.AuthorizeClientIDSecret(ctx, "c1", "secret-1"); err != nil {
		t.Fatalf("valid secret rejected: %v", err)
	}
	if err := store.AuthorizeClientIDSecret(ctx, "c1", "wrong"); err == nil {
		t.Fatal("expected error for wrong secret")
	}
	if err := store.AuthorizeClientIDSecret(ctx, "missing", "x"); err == nil {
		t.Fatal("expected error for missing client")
	}
}

// TestTokenLifecycle verifies access/refresh token creation and refresh lookup.
func TestTokenLifecycle(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// CreateAccessToken
	accessID, exp, err := store.CreateAccessToken(ctx, &authRequest{subject: "u1", clientID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if accessID == "" || exp.Before(time.Now()) {
		t.Fatalf("bad access token: id=%q exp=%v", accessID, exp)
	}

	// CreateAccessAndRefreshTokens
	accessID2, refreshToken, exp2, err := store.CreateAccessAndRefreshTokens(ctx, &authRequest{subject: "u1", clientID: "c1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if accessID2 == "" || refreshToken == "" || exp2.Before(time.Now()) {
		t.Fatalf("bad tokens: id=%q refresh=%q exp=%v", accessID2, refreshToken, exp2)
	}

	// TokenRequestByRefreshToken
	req, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	if err != nil {
		t.Fatalf("refresh lookup failed: %v", err)
	}
	if req.GetSubject() != "u1" {
		t.Fatalf("refresh subject = %s, want u1", req.GetSubject())
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, "bad-token"); err == nil {
		t.Fatal("expected error for bad refresh token")
	}

	// GetRefreshTokenInfo
	userID, tokenID, err := store.GetRefreshTokenInfo(ctx, "c1", refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if userID != "u1" || tokenID != refreshToken {
		t.Fatalf("refresh info = (%s, %s), want (u1, %s)", userID, tokenID, refreshToken)
	}
	if _, _, err := store.GetRefreshTokenInfo(ctx, "c1", "bad"); err == nil {
		t.Fatal("expected error for bad refresh token info")
	}

	// RevokeToken
	if err := store.RevokeToken(ctx, refreshToken, "u1", "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refreshToken); err == nil {
		t.Fatal("expected error after revoke")
	}
}

// TestTerminateAndUserinfo verifies session termination and userinfo stubs.
func TestTerminateAndUserinfo(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := store.TerminateSession(ctx, "u1", "c1"); err != nil {
		t.Fatalf("TerminateSession: %v", err)
	}
	if err := store.SetUserinfoFromScopes(ctx, &oidc.UserInfo{}, "u1", "c1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfoFromScopes: %v", err)
	}
	if err := store.SetUserinfoFromToken(ctx, &oidc.UserInfo{}, "tok", "u1", "origin"); err != nil {
		t.Fatalf("SetUserinfoFromToken: %v", err)
	}
	if err := store.SetIntrospectionFromToken(ctx, &oidc.IntrospectionResponse{}, "tok", "u1", "c1"); err != nil {
		t.Fatalf("SetIntrospectionFromToken: %v", err)
	}
	claims, err := store.GetPrivateClaimsFromScopes(ctx, "u1", "c1", []string{"openid"})
	if err != nil || claims == nil {
		t.Fatalf("GetPrivateClaimsFromScopes = %v, %v", claims, err)
	}
	scopes, err := store.ValidateJWTProfileScopes(ctx, "u1", []string{"openid"})
	if err != nil || len(scopes) != 1 {
		t.Fatalf("ValidateJWTProfileScopes = %v, %v", scopes, err)
	}
}

// TestSigningKeyAndKeyByID verifies signing key and key-by-id lookup.
func TestSigningKeyAndKeyByID(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	signing, err := store.SigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if signing.SignatureAlgorithm() != jose.RS256 {
		t.Fatalf("alg = %s, want RS256", signing.SignatureAlgorithm())
	}
	if signing.Key() == nil || signing.ID() == "" {
		t.Fatal("signing key missing key or id")
	}

	algs, err := store.SignatureAlgorithms(ctx)
	if err != nil || len(algs) != 1 {
		t.Fatalf("algs = %v, %v", algs, err)
	}

	jwk, err := store.GetKeyByIDAndClientID(ctx, signing.ID(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if jwk.KeyID != signing.ID() {
		t.Fatalf("jwk keyID = %s, want %s", jwk.KeyID, signing.ID())
	}
	if _, err := store.GetKeyByIDAndClientID(ctx, "missing", "c1"); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// TestAuthRequestGetters verifies the authRequest accessor methods.
func TestAuthRequestGetters(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:      "c1",
		Scopes:        []string{"openid"},
		RedirectURI:   "https://x/cb",
		ResponseType:  oidc.ResponseTypeCode,
		ResponseMode:  oidc.ResponseModeQuery,
		State:         "st",
		Nonce:         "nn",
		CodeChallenge: "challenge",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	if ar.GetID() == "" {
		t.Fatal("empty id")
	}
	if ar.GetACR() != "" {
		t.Fatalf("acr = %q, want empty", ar.GetACR())
	}
	if len(ar.GetAMR()) != 0 {
		t.Fatalf("amr = %v, want empty", ar.GetAMR())
	}
	if len(ar.GetAudience()) != 1 || ar.GetAudience()[0] != "c1" {
		t.Fatalf("audience = %v, want [c1]", ar.GetAudience())
	}
	if ar.GetAuthTime().IsZero() {
		t.Fatal("auth time is zero")
	}
	if ar.GetClientID() != "c1" {
		t.Fatalf("clientID = %s, want c1", ar.GetClientID())
	}
	if ar.GetCodeChallenge() == nil || ar.GetCodeChallenge().Challenge != "challenge" {
		t.Fatalf("code challenge = %+v", ar.GetCodeChallenge())
	}
	if ar.GetNonce() != "nn" {
		t.Fatalf("nonce = %s, want nn", ar.GetNonce())
	}
	if ar.GetRedirectURI() != "https://x/cb" {
		t.Fatalf("redirect = %s", ar.GetRedirectURI())
	}
	if ar.GetResponseType() != oidc.ResponseTypeCode {
		t.Fatalf("response type = %s", ar.GetResponseType())
	}
	if ar.GetResponseMode() != oidc.ResponseModeQuery {
		t.Fatalf("response mode = %s", ar.GetResponseMode())
	}
	if len(ar.GetScopes()) != 1 || ar.GetScopes()[0] != "openid" {
		t.Fatalf("scopes = %v", ar.GetScopes())
	}
	if ar.GetState() != "st" {
		t.Fatalf("state = %s, want st", ar.GetState())
	}
	if ar.GetSubject() != "" {
		t.Fatalf("subject = %s, want empty", ar.GetSubject())
	}
	if ar.Done() {
		t.Fatal("done should be false")
	}
	_ = now
}

// TestRefreshTokenRequestGetters verifies refresh token request accessors.
func TestRefreshTokenRequestGetters(t *testing.T) {
	r := &refreshTokenRequest{
		subject:  "u1",
		clientID: "c1",
		scopes:   []string{"openid"},
		amr:      []string{"pwd"},
		authTime: time.Now(),
	}
	if r.GetAMR()[0] != "pwd" {
		t.Fatalf("amr = %v", r.GetAMR())
	}
	if r.GetAudience()[0] != "c1" {
		t.Fatalf("audience = %v", r.GetAudience())
	}
	if r.GetAuthTime().IsZero() {
		t.Fatal("auth time zero")
	}
	if r.GetClientID() != "c1" {
		t.Fatalf("clientID = %s", r.GetClientID())
	}
	if r.GetScopes()[0] != "openid" {
		t.Fatalf("scopes = %v", r.GetScopes())
	}
	if r.GetSubject() != "u1" {
		t.Fatalf("subject = %s", r.GetSubject())
	}
	r.SetCurrentScopes([]string{"email"})
	if r.GetScopes()[0] != "email" {
		t.Fatalf("scopes after set = %v", r.GetScopes())
	}
}

// TestClientInterface verifies the op.Client interface methods.
func TestClientInterface(t *testing.T) {
	c := &Client{
		ID:               "c1",
		Secret:           "s",
		RedirectURIsList: []string{"https://x/cb"},
		Scopes:           []string{"openid", "profile"},
	}
	if c.GetID() != "c1" {
		t.Fatalf("id = %s", c.GetID())
	}
	if len(c.RedirectURIs()) != 1 || c.RedirectURIs()[0] != "https://x/cb" {
		t.Fatalf("redirects = %v", c.RedirectURIs())
	}
	if c.PostLogoutRedirectURIs() != nil {
		t.Fatal("post logout should be nil")
	}
	if c.ApplicationType() != 0 {
		t.Fatalf("app type = %v", c.ApplicationType())
	}
	if c.AuthMethod() == "" {
		t.Fatal("auth method empty")
	}
	if len(c.ResponseTypes()) != 1 {
		t.Fatalf("response types = %v", c.ResponseTypes())
	}
	if len(c.GrantTypes()) != 2 {
		t.Fatalf("grant types = %v", c.GrantTypes())
	}
	if c.LoginURL("x") != "" {
		t.Fatal("login url should be empty")
	}
	if c.AccessTokenType() == 0 {
		t.Fatal("access token type zero")
	}
	if c.IDTokenLifetime() <= 0 {
		t.Fatal("id token lifetime <= 0")
	}
	if c.DevMode() {
		t.Fatal("dev mode should be false")
	}
	if c.RestrictAdditionalIdTokenScopes() != nil {
		t.Fatal("restrict id scopes should be nil")
	}
	if c.RestrictAdditionalAccessTokenScopes() != nil {
		t.Fatal("restrict access scopes should be nil")
	}
	if !c.IsScopeAllowed("openid") {
		t.Fatal("openid scope should be allowed")
	}
	if c.IsScopeAllowed("admin") {
		t.Fatal("admin scope should not be allowed")
	}
	if c.IDTokenUserinfoClaimsAssertion() {
		t.Fatal("userinfo claims assertion should be false")
	}
	if c.ClockSkew() != 0 {
		t.Fatal("clock skew should be 0")
	}
}

// TestSigningKeyAndKeyTypes verifies the signingKey and key types.
func TestSigningKeyAndKeyTypes(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	signing, err := store.SigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sk := signing.(*signingKey)
	if sk.SignatureAlgorithm() != jose.RS256 {
		t.Fatalf("alg = %s", sk.SignatureAlgorithm())
	}
	if sk.Key() == nil {
		t.Fatal("key nil")
	}
	if sk.ID() == "" {
		t.Fatal("id empty")
	}

	keys, err := store.KeySet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k := keys[0].(*key)
	if k.ID() != sk.ID() {
		t.Fatalf("key id = %s, want %s", k.ID(), sk.ID())
	}
	if k.Algorithm() != jose.RS256 {
		t.Fatalf("key alg = %s", k.Algorithm())
	}
	if k.Use() != "sig" {
		t.Fatalf("key use = %s, want sig", k.Use())
	}
	if k.Key() == nil {
		t.Fatal("key key nil")
	}
}
