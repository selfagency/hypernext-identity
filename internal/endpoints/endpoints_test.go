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
	"github.com/selfagency/sovereign/internal/tenant"
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

// alice returns a seeded tenant whose internal ID differs from its handle,
// mirroring production (ID "identity", Handle "id.<domain>").
func alice() *tenant.Tenant {
	return &tenant.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web", DID: "did:web:alice.example.com"}
}

// ctxWith returns a request context carrying the given tenant.
func ctxWith(t *tenant.Tenant) context.Context {
	return tenant.WithTenant(context.Background(), t)
}

// TestKeysEndpointUsesTenantID verifies .keys resolves the tenant from the
// request context (by internal ID) and serves only that tenant's active SSH
// keys, excluding revoked ones.
func TestKeysEndpointUsesTenantID(t *testing.T) {
	s := newTestStore(t)
	ctx := ctxWith(alice())
	// Seed the tenant's keys under its internal ID "t1", NOT its handle.
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "ssh-ed25519 AAAA active"})
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k2", TenantID: "t1", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp2", KeyMaterial: "ssh-ed25519 BBBB revoked"})
	_ = s.RevokePublicKey(ctx, "t1", "a1", "k2")

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/alice.example.com.keys", http.NoBody).WithContext(ctx)
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

// TestKeysEndpointNoTenant404 verifies .keys returns 404 when no tenant is
// present in the request context.
func TestKeysEndpointNoTenant404(t *testing.T) {
	s := newTestStore(t)

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/alice.example.com.keys", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestCrossTenantIDOR verifies an attacker tenant cannot read a victim's
// keys or proofs even when the URL path names the victim (C4).
func TestCrossTenantIDOR(t *testing.T) {
	s := newTestStore(t)
	attacker := &tenant.Tenant{ID: "t-attacker", Handle: "attacker.example.com"}

	// Victim's data, seeded under the victim's internal ID.
	_ = s.CreatePublicKey(context.Background(), &store.PublicKey{ID: "vk1", TenantID: "t-victim", AccountID: "a1", KeyType: "ssh", Fingerprint: "vfp", KeyMaterial: "ssh-ed25519 VICTIM"})
	now := time.Now()
	_ = s.CreateProofClaim(context.Background(), &store.ProofClaim{
		ID: "vc1", TenantID: "t-victim", AccountID: "a1",
		AnchorType: "did", AnchorValue: "did:web:victim.example.com", Service: "mastodon", ClaimLocation: "https://fosstodon.org/@victim",
		ExpectedToken: "tok", Status: "verified", LastCheckedAt: &now, CreatedAt: now,
	})

	// Attacker requests /victim.keys and /victim's proofs, with attacker in context.
	attackerCtx := tenant.WithTenant(context.Background(), attacker)
	keysReq := httptest.NewRequest("GET", "/victim.example.com.keys", http.NoBody).WithContext(attackerCtx)
	keysRec := httptest.NewRecorder()
	(&KeysHandler{Store: s}).ServeHTTP(keysRec, keysReq)
	if keysRec.Code != http.StatusOK {
		t.Fatalf("keys status = %d, want 200", keysRec.Code)
	}
	if strings.Contains(keysRec.Body.String(), "VICTIM") {
		t.Fatalf("attacker read victim's keys: %q", keysRec.Body.String())
	}

	proofsReq := httptest.NewRequest("GET", "/.well-known/proofs", http.NoBody).WithContext(attackerCtx)
	proofsRec := httptest.NewRecorder()
	(&ProofsHandler{Store: s}).ServeHTTP(proofsRec, proofsReq)
	if proofsRec.Code != http.StatusOK {
		t.Fatalf("proofs status = %d, want 200", proofsRec.Code)
	}
	if strings.Contains(proofsRec.Body.String(), "fosstodon.org/@victim") {
		t.Fatalf("attacker read victim's proofs: %q", proofsRec.Body.String())
	}
}

// TestKeysEndpointHostMismatch verifies the keys handler serves only the
// tenant from context, not a tenant named in the URL path (C4). Requesting
// /victim.keys with attacker in context must not serve victim's keys.
func TestKeysEndpointHostMismatch(t *testing.T) {
	s := newTestStore(t)
	_ = s.CreatePublicKey(context.Background(), &store.PublicKey{ID: "k1", TenantID: "t-victim", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "ssh-ed25519 VICTIM"})

	h := &KeysHandler{Store: s}
	attackerCtx := tenant.WithTenant(context.Background(), &tenant.Tenant{ID: "t-attacker", Handle: "attacker.example.com"})
	req := httptest.NewRequest("GET", "/victim.example.com.keys", http.NoBody).WithContext(attackerCtx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "VICTIM") {
		t.Fatalf("served victim's key on attacker tenant: %q", rec.Body.String())
	}
}

// TestGPGEndpoint verifies .gpg serves PGP keys.
func TestGPGEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := ctxWith(alice())
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "pgp", Fingerprint: "fp1", KeyMaterial: "-----BEGIN PGP PUBLIC KEY BLOCK-----"})

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/alice.example.com.gpg", http.NoBody).WithContext(ctx)
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
	ctx := ctxWith(alice())
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "pgp", Fingerprint: "fp1", KeyMaterial: "-----BEGIN PGP PUBLIC KEY BLOCK-----"})

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/openpgpkey/hu/abc123", http.NoBody).WithContext(ctx)
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
	ctx := ctxWith(alice())
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "x"})

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/keys", http.NoBody).WithContext(ctx)
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
	ctx := ctxWith(alice())
	now := time.Now()
	_ = s.CreateProofClaim(ctx, &store.ProofClaim{
		ID: "c1", TenantID: "t1", AccountID: "a1",
		AnchorType: "did", AnchorValue: "did:plc:x", Service: "mastodon", ClaimLocation: "https://fosstodon.org/@alice",
		ExpectedToken: "tok", Status: "verified", LastCheckedAt: &now, CreatedAt: now,
	})

	h := &ProofsHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/proofs", http.NoBody).WithContext(ctx)
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
	ctx := ctxWith(alice())
	h := &ProofsHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/proofs", http.NoBody).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"claims":[]`) {
		t.Fatalf("empty claims: %q", rec.Body.String())
	}
}

// TestProofsEndpointNoTenant404 verifies proofs returns 404 when no tenant is
// present in the request context.
func TestProofsEndpointNoTenant404(t *testing.T) {
	s := newTestStore(t)
	h := &ProofsHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/proofs", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestProofsEndpointStoreError verifies proofs returns 500 when the store
// query fails.
func TestProofsEndpointStoreError(t *testing.T) {
	s := newTestStore(t)
	_ = s.DB().Close() // force store errors
	ctx := ctxWith(alice())
	h := &ProofsHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/proofs", http.NoBody).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestWKDEndpointNoTenant404 verifies WKD returns 404 when no tenant is
// present in the request context.
func TestWKDEndpointNoTenant404(t *testing.T) {
	s := newTestStore(t)
	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/openpgpkey/hu/abc123", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestWKDEndpointNoActiveKey404 verifies WKD returns 404 when the tenant has
// no active PGP key.
func TestWKDEndpointNoActiveKey404(t *testing.T) {
	s := newTestStore(t)
	ctx := ctxWith(alice())
	// Only a revoked PGP key exists, so no active key to serve.
	_ = s.CreatePublicKey(ctx, &store.PublicKey{ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "pgp", Fingerprint: "fp1", KeyMaterial: "x"})
	_ = s.RevokePublicKey(ctx, "t1", "a1", "k1")

	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/openpgpkey/hu/abc123", http.NoBody).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestWKDEndpointStoreError verifies WKD returns 500 when the store query
// fails.
func TestWKDEndpointStoreError(t *testing.T) {
	s := newTestStore(t)
	_ = s.DB().Close()
	ctx := ctxWith(alice())
	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/.well-known/openpgpkey/hu/abc123", http.NoBody).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestKeysPageEndpointNoTenant404 verifies /keys returns 404 when no tenant
// is present in the request context.
func TestKeysPageEndpointNoTenant404(t *testing.T) {
	s := newTestStore(t)
	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/keys", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestKeysPageEndpointStoreError verifies /keys returns 500 when the store
// query fails.
func TestKeysPageEndpointStoreError(t *testing.T) {
	s := newTestStore(t)
	_ = s.DB().Close()
	ctx := ctxWith(alice())
	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/keys", http.NoBody).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestKeysEndpointStoreError verifies .keys returns 500 when the store query
// fails.
func TestKeysEndpointStoreError(t *testing.T) {
	s := newTestStore(t)
	_ = s.DB().Close()
	ctx := ctxWith(alice())
	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/alice.example.com.keys", http.NoBody).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestKeysHandlerUnknownPath404 verifies an unmatched path returns 404.
func TestKeysHandlerUnknownPath404(t *testing.T) {
	s := newTestStore(t)
	h := &KeysHandler{Store: s}
	req := httptest.NewRequest("GET", "/unknown", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
