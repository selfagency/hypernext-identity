package atproto

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/selfagency/sovereign/internal/auth"
)

// atprotoSessionTTL is the lifetime of an atproto session access JWT.
const atprotoSessionTTL = 15 * time.Minute

// atprotoSession is the claim set for an atproto session JWT.
type atprotoSession struct {
	Subject string `json:"sub"`
	Did     string `json:"did"`
	Expiry  int64  `json:"exp"`
	Issued  int64  `json:"iat"`
	ID      string `json:"jti"`
}

// createSession implements com.atproto.server.createSession. It accepts a
// validated access token (the passkey-authenticated identity) and mints
// atproto session access + refresh JWTs.
func (s *XRPCServer) createSession(w http.ResponseWriter, r *http.Request) {
	if s.SigningKey == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "signing key not configured")
		return
	}
	var in struct {
		AccessJwt string `json:"accessJwt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "bad body")
		return
	}
	if in.AccessJwt == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "accessJwt is required")
		return
	}
	// Validate the passkey-authenticated access token.
	claims, err := auth.ValidateAccessToken(s.SigningKey, in.AccessJwt, s.Issuer, s.Audience)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "invalid access token")
		return
	}
	did := claims.Subject
	access, err := s.mintSessionJWT(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	refresh, err := s.mintSessionJWT(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"accessJwt":  access,
		"refreshJwt": refresh,
		"did":        did,
		"handle":     did,
	})
}

// mintSessionJWT signs an atproto session JWT for the given DID.
func (s *XRPCServer) mintSessionJWT(did string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.SigningKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	now := time.Now()
	id, err := newID()
	if err != nil {
		return "", err
	}
	claims := atprotoSession{
		Subject: did,
		Did:     did,
		Expiry:  now.Add(atprotoSessionTTL).Unix(),
		Issued:  now.Unix(),
		ID:      id,
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// newID returns a random hex ID for a JWT jti claim.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Reader.Read(b); err != nil {
		return "", fmt.Errorf("atproto: generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
