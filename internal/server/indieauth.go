package server

import (
	"context"
	"crypto/rsa"
	"net/http"
	"sync"
	"time"

	"go.hacdias.com/indielib/indieauth"

	"github.com/selfagency/sovereign/internal/auth"
	ia "github.com/selfagency/sovereign/internal/protocols/indieauth"
)

// indieauthIssuer adapts the auth package's token minting to the IndieAuth
// TokenIssuer interface.
type indieauthIssuer struct {
	key *rsa.PrivateKey
}

// IssueForProfile mints an access token for an IndieAuth identity URL.
func (i *indieauthIssuer) IssueForProfile(ctx context.Context, profileURL string, scopes []string) (string, error) {
	return auth.IssueForProfile(i.key, profileURL, scopes)
}

// indieAuthSessionStore persists authorization requests between the authorize
// and token steps, keyed by state, with a TTL.
type indieAuthSessionStore struct {
	mu   sync.Mutex
	data map[string]indieAuthSessionEntry
}

type indieAuthSessionEntry struct {
	req       *indieauth.AuthenticationRequest
	expiresAt time.Time
}

func newIndieAuthSessionStore() *indieAuthSessionStore {
	return &indieAuthSessionStore{data: map[string]indieAuthSessionEntry{}}
}

func (s *indieAuthSessionStore) put(state string, req *indieauth.AuthenticationRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = indieAuthSessionEntry{req: req, expiresAt: time.Now().Add(5 * time.Minute)}
}

func (s *indieAuthSessionStore) get(state string) (*indieauth.AuthenticationRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[state]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(s.data, state)
		return nil, false
	}
	return e.req, true
}

// indieAuthAuthorize handles the IndieAuth authorization endpoint. It parses
// the authorization request, stores it by state, and redirects back with a
// code.
func indieAuthAuthorize(b *ia.Bridge, sessions *indieAuthSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authReq, err := b.ParseAuthorization(r)
		if err != nil {
			http.Error(w, "invalid authorization request: "+err.Error(), http.StatusBadRequest)
			return
		}
		sessions.put(authReq.State, authReq)
		// Auto-approve first-party: the identity host is the only client.
		redirect := authReq.RedirectURI + "?code=" + authReq.State
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

// indieAuthToken handles the IndieAuth token endpoint. It validates the token
// exchange against the stored authorization request and mints an access token.
func indieAuthToken(b *ia.Bridge, sessions *indieAuthSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		state := r.FormValue("code")
		authReq, ok := sessions.get(state)
		if !ok {
			http.Error(w, "unknown or expired authorization code", http.StatusBadRequest)
			return
		}
		if err := b.ValidateTokenExchange(authReq, r); err != nil {
			http.Error(w, "invalid token exchange: "+err.Error(), http.StatusBadRequest)
			return
		}
		// The identity URL is the 'me' form value on the token exchange.
		me := r.FormValue("me")
		if me == "" {
			http.Error(w, "me is required", http.StatusBadRequest)
			return
		}
		tok, err := b.IssueToken(r.Context(), me, authReq.Scopes)
		if err != nil {
			http.Error(w, "token issuance failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + tok + `","token_type":"Bearer"}`))
	}
}
