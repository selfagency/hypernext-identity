package solid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/storage"
)

// fakeOwnerACL is an ownership-based ACL that grants the owner write and
// everyone read (mirrors the wiring ACLChecker's public-read default).
type fakeOwnerACL struct {
	ownerWebID string
}

func (f fakeOwnerACL) CanRead(_ context.Context, _ string, agent Agent) bool {
	return true // public read
}

func (f fakeOwnerACL) CanWrite(_ context.Context, _ string, agent Agent) bool {
	return agent.WebID == f.ownerWebID
}

// TestWACGrantToAuthenticatedAgent proves an .acl granting Read to
// AuthenticatedAgent allows a logged-in non-owner.
func TestWACGrantToAuthenticatedAgent(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	// ACL resource granting Read to any authenticated agent.
	acl := `@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#r> a acl:Authorization;
    acl:agentClass acl:AuthenticatedAgent;
    acl:accessTo <./docs/x>;
    acl:mode acl:Read.`
	if _, err := fs.Put(context.Background(), "docs/x.acl", strings.NewReader(acl), "text/turtle"); err != nil {
		t.Fatal(err)
	}

	// Owner is alice; the requesting agent is bob (non-owner).
	wac := &WACChecker{
		Backend: func(string) storage.Backend { return fs },
		Owner:   fakeOwnerACL{ownerWebID: "https://alice.example.com/profile#me"},
	}
	agent := Agent{WebID: "https://bob.example.com/profile#me"}
	if !wac.CanRead(context.Background(), "docs/x", agent) {
		t.Fatal("WAC should grant Read to authenticated non-owner")
	}
	// But not Write (the ACL only grants Read).
	if wac.CanWrite(context.Background(), "docs/x", agent) {
		t.Fatal("WAC should deny Write to non-owner")
	}
}

// TestWACFallbackToOwner proves a missing .acl falls back to the ownership
// checker.
func TestWACFallbackToOwner(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	wac := &WACChecker{
		Backend: func(string) storage.Backend { return fs },
		Owner:   fakeOwnerACL{ownerWebID: "https://alice.example.com/profile#me"},
	}
	// No .acl exists -> ownership fallback: owner can write, others cannot.
	if !wac.CanWrite(context.Background(), "docs/x", Agent{WebID: "https://alice.example.com/profile#me"}) {
		t.Fatal("owner should write via fallback")
	}
	if wac.CanWrite(context.Background(), "docs/x", Agent{WebID: "https://bob.example.com/profile#me"}) {
		t.Fatal("non-owner should not write via fallback")
	}
}

// TestWACDenySpecificAgent proves an .acl can deny a specific agent.
func TestWACDenySpecificAgent(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	// ACL granting Write only to alice.
	acl := `@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#r> a acl:Authorization;
    acl:agent <https://alice.example.com/profile#me>;
    acl:accessTo <./docs/x>;
    acl:mode acl:Read, acl:Write.`
	if _, err := fs.Put(context.Background(), "docs/x.acl", strings.NewReader(acl), "text/turtle"); err != nil {
		t.Fatal(err)
	}
	wac := &WACChecker{
		Backend: func(string) storage.Backend { return fs },
		Owner:   fakeOwnerACL{ownerWebID: "https://alice.example.com/profile#me"},
	}
	if !wac.CanWrite(context.Background(), "docs/x", Agent{WebID: "https://alice.example.com/profile#me"}) {
		t.Fatal("alice should write per ACL")
	}
	if wac.CanWrite(context.Background(), "docs/x", Agent{WebID: "https://bob.example.com/profile#me"}) {
		t.Fatal("bob should not write per ACL")
	}
}

// TestWACServerIntegration proves the Solid server uses the WAC checker.
func TestWACServerIntegration(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	// Seed a resource and an ACL granting Write to bob.
	if _, err := fs.Put(context.Background(), "docs/x", strings.NewReader("<> a <http://example.com/Thing>."), "text/turtle"); err != nil {
		t.Fatal(err)
	}
	acl := `@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#r> a acl:Authorization;
    acl:agent <https://bob.example.com/profile#me>;
    acl:accessTo <./docs/x>;
    acl:mode acl:Read, acl:Write.`
	if _, err := fs.Put(context.Background(), "docs/x.acl", strings.NewReader(acl), "text/turtle"); err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		Backend: func(string) storage.Backend { return fs },
		ACL: &WACChecker{
			Backend: func(string) storage.Backend { return fs },
			Owner:   fakeOwnerACL{ownerWebID: "https://alice.example.com/profile#me"},
		},
		Tokens: fakeTokenValidator{subject: "https://bob.example.com/profile#me"},
	}
	h := withTenant(srv, "alice.example.com")

	// Bob (granted by ACL) can PUT.
	req := httptest.NewRequest("PUT", "/docs/x", strings.NewReader("<> a <http://example.com/Thing>."))
	req.Host = "alice.example.com"
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("bob PUT = %d, want 201", rec.Code)
	}
}
