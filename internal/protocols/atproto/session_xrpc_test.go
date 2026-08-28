package atproto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/storage"
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
	}

	// Mint an access token for the passkey-authenticated identity.
	accessTok, err := auth.MintAccessToken(key, "did:plc:abc123", []string{"atproto"}, auth.AccessTokenTTL)
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
