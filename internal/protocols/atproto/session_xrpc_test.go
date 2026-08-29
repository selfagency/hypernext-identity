package atproto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/storage"
)

// testIssuer and testAudience are the expected iss/aud for atproto session
// access-token validation.
const (
	testIssuer   = "https://id.example.com"
	testAudience = "example.com"
)

// TestCreateSessionWithAccessToken proves createSession accepts a validated
// access token (the passkey-authenticated identity) and mints atproto session
// JWTs.
func TestCreateSessionWithAccessToken(t *testing.T) {
	s := newTestStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	x := &XRPCServer{
		Store:      s,
		Backend:    func(string) storage.Backend { return fs },
		SigningKey: key,
		Issuer:     testIssuer,
		Audience:   testAudience,
	}

	// Mint an access token for the passkey-authenticated identity.
	accessTok, err := auth.MintAccessToken(key, "did:plc:abc123", []string{"atproto"}, auth.AccessTokenTTL, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"accessJwt":"` + accessTok + `"}`
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.server.createSession", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("createSession = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var sess struct {
		AccessJwt  string `json:"accessJwt"`
		RefreshJwt string `json:"refreshJwt"`
		Did        string `json:"did"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatalf("decode createSession: %v", err)
	}
	if sess.AccessJwt == "" || sess.RefreshJwt == "" {
		t.Fatalf("createSession missing JWTs: %+v", sess)
	}
	if sess.Did != "did:plc:abc123" {
		t.Fatalf("createSession did = %q, want did:plc:abc123", sess.Did)
	}
}

// TestCreateSessionRejectsBadToken proves createSession rejects an invalid
// access token.
func TestCreateSessionRejectsBadToken(t *testing.T) {
	s := newTestStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	x := &XRPCServer{
		Store:      s,
		Backend:    func(string) storage.Backend { return fs },
		SigningKey: key,
	}

	body := `{"accessJwt":"not-a-valid-token"}`
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.server.createSession", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("createSession bad token = %d, want 401", rec.Code)
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
