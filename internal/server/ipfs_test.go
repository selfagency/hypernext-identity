package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	cid "github.com/ipfs/go-cid"

	"github.com/selfagency/sovereign/internal/store"
)

// newTestStore opens an in-memory SQLite store for server unit tests.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// fakeIPFSBackend is a controllable ipfspin.Backend for unit tests.
type fakeIPFSBackend struct {
	pinErr error
}

func (f *fakeIPFSBackend) Pin(_ context.Context, _ cid.Cid) error { return f.pinErr }
func (f *fakeIPFSBackend) Unpin(_ context.Context, _ cid.Cid) error {
	return nil
}

func (f *fakeIPFSBackend) Status(_ context.Context, _ cid.Cid) (string, error) {
	return "pinned", nil
}

// TestIPFSPinMissingCID proves POST /ipfs/pin without a cid is a 400.
func TestIPFSPinMissingCID(t *testing.T) {
	st := newTestStore(t)
	b := newIPFSBroker(st, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ipfs/pin", http.NoBody)
	b.pin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestIPFSPinBackendError proves a backend failure surfaces a 500.
func TestIPFSPinBackendError(t *testing.T) {
	st := newTestStore(t)
	b := newIPFSBroker(st, &fakeIPFSBackend{pinErr: errors.New("kubo down")})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ipfs/pin?cid=bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", http.NoBody)
	b.pin(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestIPFSPinNoBackendStillPersists proves a nil backend records the pin in
// the store (dev fallback).
func TestIPFSPinNoBackendStillPersists(t *testing.T) {
	st := newTestStore(t)
	b := newIPFSBroker(st, nil)
	cidStr := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ipfs/pin?cid="+cidStr, http.NoBody)
	b.pin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), cidStr) {
		t.Fatalf("body missing cid: %q", rec.Body.String())
	}
	p, err := st.GetIPFSPin(context.Background(), cidStr)
	if err != nil || p.Status != "pinned" {
		t.Fatalf("store pin = %+v, %v", p, err)
	}
}

// TestIPFSStatusMissingCID proves GET /ipfs/pin/ without a cid is a 400.
func TestIPFSStatusMissingCID(t *testing.T) {
	st := newTestStore(t)
	b := newIPFSBroker(st, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ipfs/pin/", http.NoBody)
	b.status(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestIPFSStatusNotFound proves an unpinned CID returns 404.
func TestIPFSStatusNotFound(t *testing.T) {
	st := newTestStore(t)
	b := newIPFSBroker(st, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ipfs/pin/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", http.NoBody)
	b.status(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestMustCIDInvalid proves an invalid CID string yields a zero CID without
// panicking.
func TestMustCIDInvalid(t *testing.T) {
	if got := mustCID("not-a-cid"); got.Defined() {
		t.Fatalf("mustCID(%q) = %v, want zero CID", "not-a-cid", got)
	}
}

var _ = store.ErrNotFound
