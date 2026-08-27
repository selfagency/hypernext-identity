package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/store"
)

// newTestStore opens an in-memory SQLite store.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestKeysEndpoint verifies .keys serves active SSH keys, excludes revoked.
func TestKeysEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "alice.example.com", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "ssh-ed25519 AAAA active"})
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k2", TenantID: "alice.example.com", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp2", KeyMaterial: "ssh-ed25519 BBBB revoked"})
	_ = s.RevokePublicKey(ctx, "alice.example.com", "a1", "k2")

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/alice.example.com.keys", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "active") {
		t.Fatalf("missing active key: %q", body)
	}
	if strings.Contains(body, "revoked") {
		t.Fatalf("revoked key should be excluded: %q", body)
	}
}

// TestKeysEndpointHostMismatch verifies the keys handler serves only the
// host-derived tenant, not a tenant named in the URL path (C4). Requesting
// /victim.keys on attacker.example.com must not serve victim's keys.
func TestKeysEndpointHostMismatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "victim.example.com", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "ssh-ed25519 VICTIM"})

	h := &KeysHandler{Store: s}
	// Request /victim.keys but on attacker.example.com host.
	req := httptest.NewRequest("GET", "/victim.example.com.keys", http.NoBody)
	req.Host = "attacker.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "VICTIM") {
		t.Fatalf("served victim's key on attacker host: %q", rec.Body.String())
	}
}

// TestGPGEndpoint verifies .gpg serves PGP keys.
func TestGPGEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "alice.example.com", AccountID: "a1", KeyType: "pgp", Fingerprint: "fp1", KeyMaterial: "-----BEGIN PGP PUBLIC KEY BLOCK-----"})

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/alice.example.com.gpg", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "PGP PUBLIC KEY BLOCK") {
		t.Fatalf("missing PGP key: %q", rec.Body.String())
	}
}

// TestWKDEndpoint verifies WKD serves an active PGP key.
func TestWKDEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "alice.example.com", AccountID: "a1", KeyType: "pgp", Fingerprint: "fp1", KeyMaterial: "-----BEGIN PGP PUBLIC KEY BLOCK-----"})

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/openpgpkey/hu/abc123", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pgp-keys" {
		t.Fatalf("content-type = %q, want application/pgp-keys", ct)
	}
}

// TestKeysPageEndpoint verifies the /keys page lists keys with status.
func TestKeysPageEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "alice.example.com", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "x"})

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/keys", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "fp1") {
		t.Fatalf("missing fingerprint: %q", rec.Body.String())
	}
}

// TestProofsEndpoint verifies /.well-known/proofs returns verified claims.
func TestProofsEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateProofClaim(ctx, &store.ProofClaim{
		ID: "c1", TenantID: "alice.example.com", AccountID: "a1",
		AnchorType: "did", AnchorValue: "did:plc:x", Service: "mastodon", ClaimLocation: "https://fosstodon.org/@alice",
		ExpectedToken: "tok", Status: "verified", LastCheckedAt: &now, CreatedAt: now,
	})

	h := &ProofsHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/proofs", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"service":"mastodon"`) {
		t.Fatalf("missing claim: %q", body)
	}
	if !strings.Contains(body, `"anchor"`) {
		t.Fatalf("missing anchor: %q", body)
	}
}

// TestProofsEndpointEmpty verifies empty verified claims returns empty JSON.
func TestProofsEndpointEmpty(t *testing.T) {
	s := newTestStore(t)
	h := &ProofsHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/proofs", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"claims":[]`) {
		t.Fatalf("empty claims: %q", rec.Body.String())
	}
}
