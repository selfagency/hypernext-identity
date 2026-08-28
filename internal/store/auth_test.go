package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newAuthTestStore opens a temp SQLite store.
func newAuthTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestAuthSigningKeyCRUD verifies signing key save/get.
func TestAuthSigningKeyCRUD(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()

	k := AuthSigningKey{ID: "signing-1", KeyPEM: "test-key-material", CreatedAt: time.Now()}
	if err := s.SaveAuthSigningKey(ctx, k); err != nil {
		t.Fatalf("SaveAuthSigningKey: %v", err)
	}
	got, err := s.GetAuthSigningKey(ctx, "signing-1")
	if err != nil {
		t.Fatalf("GetAuthSigningKey: %v", err)
	}
	if got.KeyPEM != k.KeyPEM {
		t.Fatalf("key_pem = %q, want %q", got.KeyPEM, k.KeyPEM)
	}
	if _, err := s.GetAuthSigningKey(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}

// TestAuthSigningKeyUpsert verifies save is idempotent by ID.
func TestAuthSigningKeyUpsert(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()
	_ = s.SaveAuthSigningKey(ctx, AuthSigningKey{ID: "signing-1", KeyPEM: "key1", CreatedAt: time.Now()})
	_ = s.SaveAuthSigningKey(ctx, AuthSigningKey{ID: "signing-1", KeyPEM: "key2", CreatedAt: time.Now()})
	got, _ := s.GetAuthSigningKey(ctx, "signing-1")
	if got.KeyPEM != "key2" {
		t.Fatalf("key_pem = %q, want key2 (upsert)", got.KeyPEM)
	}
}

// TestAuthRefreshTokenCRUD verifies refresh token save/get/delete.
func TestAuthRefreshTokenCRUD(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()
	tok := &AuthRefreshToken{Token: "tok1", Subject: "alice", ClientID: "client1", Scopes: "openid,profile", AuthTime: time.Now(), CreatedAt: time.Now()}
	if err := s.SaveAuthRefreshToken(ctx, tok); err != nil {
		t.Fatalf("SaveAuthRefreshToken: %v", err)
	}
	got, err := s.GetAuthRefreshToken(ctx, "tok1")
	if err != nil {
		t.Fatalf("GetAuthRefreshToken: %v", err)
	}
	if got.Subject != "alice" || got.ClientID != "client1" || got.Scopes != "openid,profile" {
		t.Fatalf("got = %+v", got)
	}
	if _, err := s.GetAuthRefreshToken(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	if err := s.DeleteAuthRefreshToken(ctx, "tok1"); err != nil {
		t.Fatalf("DeleteAuthRefreshToken: %v", err)
	}
	if _, err := s.GetAuthRefreshToken(ctx, "tok1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

// TestAuthRefreshTokenByHash verifies lookup by hashed value + expiry/revoke.
func TestAuthRefreshTokenByHash(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "hash1", Subject: "alice", ClientID: "c1", Scopes: "openid", AuthTime: time.Now(), CreatedAt: time.Now()})
	subj, client, scopes, err := s.GetAuthRefreshTokenByHash(ctx, "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if subj != "alice" || client != "c1" || len(scopes) != 1 || scopes[0] != "openid" {
		t.Fatalf("by hash = %q %q %v", subj, client, scopes)
	}
	// Revoked -> ErrNotFound.
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "rev", Subject: "bob", ClientID: "c1", Scopes: "openid", AuthTime: time.Now(), RevokedAt: time.Now(), CreatedAt: time.Now()})
	if _, _, _, err := s.GetAuthRefreshTokenByHash(ctx, "rev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked = %v, want ErrNotFound", err)
	}
	// Expired -> ErrNotFound.
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "exp", Subject: "bob", ClientID: "c1", Scopes: "openid", AuthTime: time.Now(), ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now()})
	if _, _, _, err := s.GetAuthRefreshTokenByHash(ctx, "exp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired = %v, want ErrNotFound", err)
	}
}

// TestCreateUserFirstIsAdmin verifies the first user becomes the instance
// admin.
func TestCreateUserFirstIsAdmin(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByHandle(ctx, "t1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin {
		t.Fatal("first user should be admin")
	}
}

// TestCreateUserSecondNotAdmin verifies subsequent users are not admin by
// default.
func TestCreateUserSecondNotAdmin(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	if err := s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByHandle(ctx, "t1", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if u.IsAdmin {
		t.Fatal("second user should not be admin by default")
	}
}

// TestSetUserAdmin verifies the admin flag can be toggled.
func TestSetUserAdmin(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	_ = s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob"})
	if err := s.SetUserAdmin(ctx, "u2", true); err != nil {
		t.Fatal(err)
	}
	u, _ := s.UserByID(ctx, "u2")
	if !u.IsAdmin {
		t.Fatal("bob should be admin after SetUserAdmin")
	}
	if err := s.SetUserAdmin(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user = %v, want ErrNotFound", err)
	}
}

// TestCreateUserDuplicate verifies a duplicate tenant+handle is rejected.
func TestCreateUserDuplicate(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	if err := s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "alice"}); !errors.Is(err, ErrDuplicateUser) {
		t.Fatalf("duplicate = %v, want ErrDuplicateUser", err)
	}
}

// TestListUsers verifies listing users for a tenant.
func TestListUsers(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	_ = s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob"})
	users, err := s.ListUsers(ctx, "t1")
	if err != nil || len(users) != 2 {
		t.Fatalf("users = %v, %v", users, err)
	}
}

// TestClientCRUD verifies client create + lookup + list.
func TestClientCRUD(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateClient(ctx, &Client{
		ID: "web", Secret: "s3cret", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid", "profile"},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := s.ClientByID(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret != "s3cret" || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Fatalf("client = %+v", c)
	}
	if len(c.Scopes) != 2 {
		t.Fatalf("scopes = %v", c.Scopes)
	}
	clients, err := s.ListClients(ctx)
	if err != nil || len(clients) != 1 {
		t.Fatalf("list = %v, %v", clients, err)
	}
	if _, err := s.ClientByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown client = %v, want ErrNotFound", err)
	}
}

// TestWebAuthnCredentialCRUD verifies credential add/list/get/update.
func TestWebAuthnCredentialCRUD(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})

	cred := &WebAuthnCredential{ID: "c1", UserID: "u1", CredentialID: []byte{1, 2, 3}, PublicKey: []byte{4, 5, 6}, SignCount: 1, Data: []byte(`{"id":"c1"}`)}
	if err := s.AddWebAuthnCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWebAuthnCredential(ctx, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" || got.SignCount != 1 || len(got.Data) == 0 {
		t.Fatalf("cred = %+v", got)
	}
	if err := s.UpdateWebAuthnSignCount(ctx, "c1", 7); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.GetWebAuthnCredential(ctx, []byte{1, 2, 3})
	if got2.SignCount != 7 {
		t.Fatalf("sign count = %d, want 7", got2.SignCount)
	}
	list, err := s.ListWebAuthnCredentials(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if _, err := s.GetWebAuthnCredential(ctx, []byte{9, 9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown cred = %v, want ErrNotFound", err)
	}
}

// TestAuditLog verifies append + list (newest first).
func TestAuditLog(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.AppendAudit(ctx, &AuditEntry{ID: "a1", TenantID: "t1", Actor: "alice", Action: "takedown", Target: "bob", Detail: "spam"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(ctx, &AuditEntry{ID: "a2", TenantID: "t1", Actor: "alice", Action: "takedown", Target: "carol", Detail: "abuse"}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListAudit(ctx, "t1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].ID != "a2" {
		t.Fatalf("first = %s, want a2 (newest first)", entries[0].ID)
	}
}

// TestUserOnboardingState verifies email, ToS, and passkey-setup flags.
func TestUserOnboardingState(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice", Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}

	// Email round-trips through UserByID.
	u, err := s.UserByID(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "a@example.com" {
		t.Fatalf("email = %q, want a@example.com", u.Email)
	}
	if u.ToSAccepted || u.PasskeySetup {
		t.Fatalf("new user should not have accepted ToS or set up passkey")
	}

	// Set email, ToS, passkey flags.
	if err := s.SetUserEmail(ctx, "u1", "b@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetToSAccepted(ctx, "u1", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasskeySetup(ctx, "u1", true); err != nil {
		t.Fatal(err)
	}
	u2, _ := s.UserByID(ctx, "u1")
	if u2.Email != "b@example.com" || !u2.ToSAccepted || !u2.PasskeySetup {
		t.Fatalf("updated user = %+v", u2)
	}

	// Unknown user -> ErrNotFound.
	if err := s.SetUserEmail(ctx, "nope", "x@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown email = %v, want ErrNotFound", err)
	}
}

// TestInviteTokenCRUD verifies invite token create/lookup/consume.
func TestInviteTokenCRUD(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}

	it := &InviteToken{ID: "inv1", TokenHash: "abc123hash", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateInviteToken(ctx, it); err != nil {
		t.Fatal(err)
	}
	got, err := s.InviteTokenByHash(ctx, "abc123hash")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" || !got.UsedAt.IsZero() {
		t.Fatalf("invite = %+v", got)
	}

	if err := s.MarkInviteTokenUsed(ctx, "inv1"); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.InviteTokenByHash(ctx, "abc123hash")
	if got2.UsedAt.IsZero() {
		t.Fatalf("invite not marked used")
	}

	if _, err := s.InviteTokenByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown invite = %v, want ErrNotFound", err)
	}
}
