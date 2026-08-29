package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// TestIPFSPinRequiresAuth verifies the IPFS pin route rejects unauthenticated
// requests.
func TestIPFSPinRequiresAuth(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)

	status, _ := ts.do(t, http.MethodPost, "/ipfs/pin?cid=bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", "id.example.com", "", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("ipfs pin no-token status = %d, want 401", status)
	}
}

// TestIPFSPinWithAdminToken verifies an admin token can pin a CID.
func TestIPFSPinWithAdminToken(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)
	ctx := context.Background()

	// Seed an admin user and mint a token.
	if err := ts.srv.store.CreateUser(ctx, &store.User{ID: "admin1", TenantID: "identity", Handle: "root"}); err != nil {
		t.Fatal(err)
	}
	tok, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), "admin1", []string{"admin"}, auth.AccessTokenTTL, "https://id."+ts.srv.cfg.Domain, ts.srv.cfg.Audience)
	if err != nil {
		t.Fatal(err)
	}

	cid := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	status, body := ts.do(t, http.MethodPost, "/ipfs/pin?cid="+cid, "id.example.com", tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("ipfs pin status = %d, want 200 (body %q)", status, body)
	}
	if !strings.Contains(body, cid) {
		t.Fatalf("ipfs pin body missing cid: %q", body)
	}
}

// TestIPFSPinStatus verifies GET /ipfs/pin/{cid} returns the pin status.
func TestIPFSPinStatus(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)
	ctx := context.Background()

	if err := ts.srv.store.CreateUser(ctx, &store.User{ID: "admin1", TenantID: "identity", Handle: "root"}); err != nil {
		t.Fatal(err)
	}
	tok, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), "admin1", []string{"admin"}, auth.AccessTokenTTL, "https://id."+ts.srv.cfg.Domain, ts.srv.cfg.Audience)
	if err != nil {
		t.Fatal(err)
	}

	cid := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	// Pin it first.
	status, _ := ts.do(t, http.MethodPost, "/ipfs/pin?cid="+cid, "id.example.com", tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("pin status = %d, want 200", status)
	}

	// Query status.
	status, body := ts.do(t, http.MethodGet, "/ipfs/pin/"+cid, "id.example.com", tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("ipfs status = %d, want 200 (body %q)", status, body)
	}
	if !strings.Contains(body, "pinned") {
		t.Fatalf("ipfs status body missing pinned: %q", body)
	}
}

var _ = httptest.NewRecorder
