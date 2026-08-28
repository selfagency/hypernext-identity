// Package admin implements the admin UI wiring for backup configuration and
// user onboarding. It exposes minimal HTTP forms for setting the backup
// schedule and creating users with one-time magic-link invites.
package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/mail"
	"github.com/selfagency/sovereign/internal/store"
)

// inviteTTL is the lifetime of a one-time magic-link invite token.
const inviteTTL = 24 * time.Hour

// UserHandler serves POST /admin/users: it creates a user with an email and
// sends a one-time magic-link invite. The raw token is emailed; only its
// SHA-256 hash is persisted (defense in depth, matching the refresh-token
// pattern).
type UserHandler struct {
	Store   *store.Store
	Sender  mail.Sender
	BaseURL string // e.g. https://id.example.com
}

// ServeHTTP handles user creation.
func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	handle := strings.TrimSpace(r.FormValue("handle"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	if email == "" || handle == "" {
		http.Error(w, "email and handle are required", http.StatusBadRequest)
		return
	}

	// Create the user in the identity tenant.
	u := &store.User{
		ID:          newID(),
		TenantID:    "identity",
		Handle:      handle,
		DisplayName: displayName,
		Email:       email,
	}
	if err := h.Store.CreateUser(r.Context(), u); err != nil {
		http.Error(w, "create user: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Generate a one-time magic link and persist its hash.
	raw := newID()
	it := &store.InviteToken{
		ID:        newID(),
		TokenHash: hashToken(raw),
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(inviteTTL),
	}
	if err := h.Store.CreateInviteToken(r.Context(), it); err != nil {
		http.Error(w, "create invite: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send the magic link.
	link := strings.TrimSuffix(h.BaseURL, "/") + "/invite/" + raw
	if err := h.Sender.Send(r.Context(), mail.Message{
		To:      email,
		Subject: "Your Sovereign invite",
		Body:    "Welcome to Sovereign. Set up your account here:\n\n" + link,
	}); err != nil {
		http.Error(w, "send invite: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte("user created; invite sent"))
}

// newID returns a random URL-safe token.
func newID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns the hex SHA-256 hash of a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
