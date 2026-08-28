package server

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// sessionCookie is the name of the HttpOnly session cookie set after a
// successful magic-link redemption.
const sessionCookie = "session"

// sessionTTL is the lifetime of a magic-link session access token.
const sessionTTL = 15 * time.Minute

// inviteHandler validates a one-time magic-link token, marks it used, mints a
// short-lived session access token (subject = user ID), sets it as an HttpOnly
// cookie, and redirects to the user panel.
func inviteHandler(st *store.Store, key *rsa.PrivateKey, baseURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Path, "/invite/")
		if raw == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		it, err := st.InviteTokenByHash(r.Context(), hashToken(raw))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if !it.UsedAt.IsZero() {
			http.Error(w, "invite already used", http.StatusGone)
			return
		}
		if time.Now().After(it.ExpiresAt) {
			http.Error(w, "invite expired", http.StatusGone)
			return
		}
		// Mark used (single-use).
		if err := st.MarkInviteTokenUsed(r.Context(), it.ID); err != nil {
			http.Error(w, "mark invite used: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Mint a short-lived session access token for the invited user.
		tok, err := auth.MintAccessToken(key, it.UserID, []string{"self"}, sessionTTL)
		if err != nil {
			http.Error(w, "mint session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// #nosec G124 -- Secure is set from baseURL (https in production);
		// HttpOnly and SameSite are always on. The cookie carries a short-lived
		// signed session token, not a long-lived credential.
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    tok,
			Path:     "/",
			HttpOnly: true,
			Secure:   strings.HasPrefix(baseURL, "https://"),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionTTL.Seconds()),
		})
		http.Redirect(w, r, "/panel", http.StatusFound)
	})
}

// hashToken returns the hex SHA-256 hash of a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
