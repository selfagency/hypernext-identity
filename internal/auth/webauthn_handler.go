package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/selfagency/sovereign/internal/store"
)

// WebAuthnHandler exposes passkey registration and login over HTTP. It
// persists credentials in the store and carries begin/finish sessions in a
// short-lived in-memory TTL store.
type WebAuthnHandler struct {
	wa      *WebAuthn
	store   *store.Store
	session *SessionStore
}

// NewWebAuthnHandler builds a WebAuthn HTTP handler for the given origin.
func NewWebAuthnHandler(rpID, rpDisplayName, origin string, st *store.Store) (*WebAuthnHandler, error) {
	wa, err := NewWebAuthn(rpID, rpDisplayName, origin)
	if err != nil {
		return nil, err
	}
	return &WebAuthnHandler{
		wa:      wa,
		store:   st,
		session: NewSessionStore(5 * time.Minute),
	}, nil
}

// RegisterBegin starts passkey registration for a user.
func (h *WebAuthnHandler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	creation, session, err := h.wa.BeginRegistration(user)
	if err != nil {
		http.Error(w, "begin registration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Put(session.Challenge, session)
	writeJSON(w, http.StatusOK, creation)
}

// RegisterFinish validates the attestation and stores the credential.
func (h *WebAuthnHandler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, err := h.sessionFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cred, err := h.wa.FinishRegistration(user, session, r)
	if err != nil {
		http.Error(w, "finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Persist the credential (full JSON for round-trip).
	data, err := json.Marshal(cred)
	if err != nil {
		http.Error(w, "marshal credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.store.AddWebAuthnCredential(r.Context(), &store.WebAuthnCredential{
		ID:           string(cred.ID),
		UserID:       user.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Data:         data,
	}); err != nil {
		http.Error(w, "store credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Delete(session.Challenge)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// LoginBegin starts passkey login for a user.
func (h *WebAuthnHandler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	assertion, session, err := h.wa.BeginLogin(user)
	if err != nil {
		http.Error(w, "begin login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Put(session.Challenge, session)
	writeJSON(w, http.StatusOK, assertion)
}

// LoginFinish validates the assertion and returns the authenticated user.
func (h *WebAuthnHandler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, err := h.sessionFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cred, err := h.wa.FinishLogin(user, session, r)
	if err != nil {
		http.Error(w, "finish login: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Update the sign count.
	if err := h.store.UpdateWebAuthnSignCount(r.Context(), string(cred.ID), cred.Authenticator.SignCount); err != nil {
		http.Error(w, "update sign count: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Delete(session.Challenge)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "user_id": user.ID})
}

// userFromRequest loads the user (by handle query param) and populates their
// WebAuthn credentials from the store.
func (h *WebAuthnHandler) userFromRequest(r *http.Request) (*User, error) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		return nil, errors.New("missing handle query param")
	}
	// The identity tenant owns all users.
	su, err := h.store.UserByHandle(r.Context(), "identity", handle)
	if err != nil {
		return nil, errors.New("unknown user")
	}
	creds, err := h.store.ListWebAuthnCredentials(r.Context(), su.ID)
	if err != nil {
		return nil, err
	}
	user := &User{ID: su.ID, Handle: su.Handle, DisplayName: su.DisplayName}
	for i := range creds {
		var wc webauthn.Credential
		if err := json.Unmarshal(creds[i].Data, &wc); err != nil {
			continue
		}
		user.Credentials = append(user.Credentials, wc)
	}
	return user, nil
}

// sessionFromRequest loads the begin/finish session by challenge.
func (h *WebAuthnHandler) sessionFromRequest(r *http.Request) (*webauthn.SessionData, error) {
	challenge := r.URL.Query().Get("challenge")
	if challenge == "" {
		return nil, errors.New("missing challenge query param")
	}
	session, ok := h.session.Get(challenge)
	if !ok {
		return nil, errors.New("session not found or expired")
	}
	return session, nil
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SessionStore is a short-lived in-memory store for WebAuthn begin/finish
// sessions, keyed by challenge. Entries expire after a TTL.
type SessionStore struct {
	mu   sync.Mutex
	ttl  time.Duration
	data map[string]sessionEntry
}

type sessionEntry struct {
	session   *webauthn.SessionData
	expiresAt time.Time
}

// NewSessionStore builds a session store with the given TTL.
func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{ttl: ttl, data: map[string]sessionEntry{}}
}

// Put stores a session keyed by challenge.
func (s *SessionStore) Put(challenge string, session *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[challenge] = sessionEntry{session: session, expiresAt: time.Now().Add(s.ttl)}
}

// Get returns a non-expired session by challenge.
func (s *SessionStore) Get(challenge string) (*webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[challenge]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(s.data, challenge)
		return nil, false
	}
	return e.session, true
}

// Delete removes a session by challenge.
func (s *SessionStore) Delete(challenge string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, challenge)
}
