package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn wraps go-webauthn for passkey registration and login.
type WebAuthn struct {
	wa *webauthn.WebAuthn
}

// NewWebAuthn builds a WebAuthn relying party for the given origin.
func NewWebAuthn(rpID, rpDisplayName, origin string) (*WebAuthn, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     []string{origin},
	})
	if err != nil {
		return nil, err
	}
	return &WebAuthn{wa: wa}, nil
}

// BeginRegistration starts passkey registration for a user, returning the
// creation options for the client and a session to store.
func (w *WebAuthn) BeginRegistration(u *User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	user := &webauthnUser{u: u}
	creation, session, err := w.wa.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	return creation, session, nil
}

// FinishRegistration validates the client's attestation response and returns
// the stored credential.
func (w *WebAuthn) FinishRegistration(u *User, session *webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	user := &webauthnUser{u: u}
	return w.wa.FinishRegistration(user, *session, r)
}

// BeginLogin starts passkey login for a user, returning assertion options.
func (w *WebAuthn) BeginLogin(u *User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	user := &webauthnUser{u: u}
	assertion, session, err := w.wa.BeginLogin(user)
	if err != nil {
		return nil, nil, err
	}
	return assertion, session, nil
}

// FinishLogin validates the client's assertion and returns the credential.
func (w *WebAuthn) FinishLogin(u *User, session *webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	user := &webauthnUser{u: u}
	return w.wa.FinishLogin(user, *session, r)
}

// webauthnUser adapts *User to go-webauthn's User interface.
type webauthnUser struct {
	u *User
}

func (w *webauthnUser) WebAuthnID() []byte          { return []byte(w.u.ID) }
func (w *webauthnUser) WebAuthnName() string        { return w.u.Handle }
func (w *webauthnUser) WebAuthnDisplayName() string { return w.u.DisplayName }
func (w *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	// The storage phase wires real credentials; for now return none.
	return nil
}

// SessionCodec serializes/deserializes WebAuthn sessions for cookie storage.
type SessionCodec struct{}

// Encode marshals a session to a JSON byte slice.
func (SessionCodec) Encode(s *webauthn.SessionData) ([]byte, error) {
	return json.Marshal(s)
}

// Decode unmarshals a session from a JSON byte slice.
func (SessionCodec) Decode(b []byte) (*webauthn.SessionData, error) {
	var s webauthn.SessionData
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ErrNoCredentials is returned when a user has no registered passkeys.
var ErrNoCredentials = errors.New("no credentials registered")
