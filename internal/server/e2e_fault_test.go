package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

// failingBackend is a storage.Backend that fails all operations. It injects
// faults to verify handlers return 500 (not panic) when storage fails.
type failingBackend struct{}

func (failingBackend) Put(ctx context.Context, key string, r io.Reader, contentType string) (storage.Blob, error) {
	return storage.Blob{}, errors.New("storage: disk full")
}

func (failingBackend) Get(ctx context.Context, key string) (io.ReadCloser, storage.Blob, error) {
	return nil, storage.Blob{}, errors.New("storage: disk full")
}

func (failingBackend) Delete(ctx context.Context, key string) error {
	return errors.New("storage: disk full")
}

func (failingBackend) List(ctx context.Context, prefix string) ([]storage.Blob, error) {
	return nil, errors.New("storage: disk full")
}

// TestE2EFaultInjection verifies the server returns 500 (not panic) when the
// storage backend fails mid-request. This is the chaos-engineering baseline:
// a failing dependency must not crash the server.
func TestE2EFaultInjection(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	// Seed an account owned by alice so Solid's ownership check passes and
	// the request reaches the (failing) storage backend.
	if err := ts.srv.store.CreateAccount(context.Background(), &store.Account{
		ID: "a1", TenantID: "t1", DID: "did:web:alice.example.com",
		WebID: "https://alice.example.com/profile/card#me",
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}

	// Replace the blob backend with a failing one.
	ts.srv.blobs = failingBackend{}

	// Mint a signed access token so authorization passes; the failure is in
	// storage.
	token, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), "https://alice.example.com/profile/card#me", []string{"rw"}, auth.AccessTokenTTL)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	// remoteStorage PUT -> 500 (storage error), not panic.
	code, _ := ts.do(t, http.MethodPut, "/rs/docs/x", "alice.example.com", token, "text/plain", []byte("data"))
	if code != http.StatusInternalServerError {
		t.Fatalf("rs PUT with failing backend = %d, want 500", code)
	}

	// remoteStorage GET -> 404 (Get error maps to not-found), not panic.
	code, _ = ts.do(t, http.MethodGet, "/rs/docs/x", "alice.example.com", token, "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("rs GET with failing backend = %d, want 404", code)
	}

	// Solid PUT -> 500 (storage error), not panic.
	code, _ = ts.do(t, http.MethodPut, "/solid/docs/x", "alice.example.com", token, "text/turtle", []byte("data"))
	if code != http.StatusInternalServerError {
		t.Fatalf("solid PUT with failing backend = %d, want 500", code)
	}
}
