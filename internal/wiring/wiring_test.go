package wiring

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hypernext/identity/internal/auth"
	"github.com/hypernext/identity/internal/authstore"
	"github.com/hypernext/identity/internal/protocols/solid"
	"github.com/hypernext/identity/internal/store"
)

// newTestStores opens temp SQLite + auth stores.
func newTestStores(t *testing.T) (st *store.Store, as *authstore.Store) {
	t.Helper()
	var err error
	st, err = store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mem, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	as, err = authstore.New(context.Background(), mem, st)
	if err != nil {
		t.Fatal(err)
	}
	return st, as
}

// TestTokenValidatorValid verifies a valid token returns scopes.
func TestTokenValidatorValid(t *testing.T) {
	_, as := newTestStores(t)
	ctx := context.Background()
	_ = as.PersistRefreshToken(ctx, "tok1", "alice", "client1", []string{"openid", "profile"})

	v := &TokenValidator{Auth: as}
	scopes, err := v.ValidateToken(ctx, "tok1")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("scopes = %v, want 2", scopes)
	}
}

// TestTokenValidatorInvalid verifies an invalid token errors.
func TestTokenValidatorInvalid(t *testing.T) {
	_, as := newTestStores(t)
	v := &TokenValidator{Auth: as}
	if _, err := v.ValidateToken(context.Background(), "bad"); err == nil {
		t.Fatal("expected error for invalid token")
	}
	if _, err := v.ValidateToken(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

// TestACLChecker verifies read/write authorization.
func TestACLChecker(t *testing.T) {
	st, _ := newTestStores(t)
	a := &ACLChecker{Store: st}
	ctx := context.Background()

	// Public agent can read.
	if !a.CanRead(ctx, "docs/x", solid.PublicAgent) {
		t.Fatal("public agent should read")
	}
	// Public agent cannot write.
	if a.CanWrite(ctx, "docs/x", solid.PublicAgent) {
		t.Fatal("public agent should not write")
	}
	// Authenticated agent can write.
	if !a.CanWrite(ctx, "docs/x", solid.Agent{WebID: "https://alice.example.com/profile/card#me"}) {
		t.Fatal("authenticated agent should write")
	}
}

// TestScopesContains verifies hierarchical scope matching.
func TestScopesContains(t *testing.T) {
	if !ScopesContains([]string{"rw"}, "r") {
		t.Fatal("rw should imply r")
	}
	if !ScopesContains([]string{"r"}, "r") {
		t.Fatal("r should match r")
	}
	if ScopesContains([]string{"r"}, "rw") {
		t.Fatal("r should not imply rw")
	}
}
