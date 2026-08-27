package activitypub

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Verifier verifies an HTTP Message Signature on a request.
type Verifier interface {
	// Verify checks the request signature against the given public key PEM.
	Verify(r *http.Request, pubKeyPEM string) error
}

// rfc9421Verifier verifies RFC 9421 HTTP Message Signatures.
type rfc9421Verifier struct{}

// cavageVerifier verifies the legacy cavage-12 HTTP Signatures.
type cavageVerifier struct{}

// VerifyDoubleKnock verifies a request signature, trying RFC 9421 first and
// falling back to cavage-12 ONLY when no RFC 9421 Signature-Input header is
// present. If Signature-Input is present but invalid, verification fails
// closed (no silent downgrade).
func VerifyDoubleKnock(r *http.Request, pubKeyPEM string, rfc9421, cavage12 Verifier) error {
	if r.Header.Get("Signature-Input") != "" {
		// RFC 9421 is authoritative when its header is present; a malformed
		// RFC signature must not fall back to cavage.
		return rfc9421.Verify(r, pubKeyPEM)
	}
	return cavage12.Verify(r, pubKeyPEM)
}

// NewRFC9421Verifier builds an RFC 9421 verifier.
func NewRFC9421Verifier() Verifier { return rfc9421Verifier{} }

// NewCavageVerifier builds a cavage-12 verifier.
func NewCavageVerifier() Verifier { return cavageVerifier{} }

// Verify implements RFC 9421 HTTP Message Signatures.
func (rfc9421Verifier) Verify(r *http.Request, pubKeyPEM string) error {
	sigInput := r.Header.Get("Signature-Input")
	sig := r.Header.Get("Signature")
	if sigInput == "" || sig == "" {
		return errors.New("missing signature headers")
	}

	// Parse the signature input: `sig1=("(request-target)" "host" "date");created=...`
	// and the signature: `sig1=:base64:`
	sigName, covered, created, expires, err := parseSignatureInput(sigInput)
	if err != nil {
		return err
	}
	// Enforce created/expires freshness (replay protection).
	now := time.Now()
	if created > 0 && now.Before(time.Unix(created, 0).Add(-clockSkew)) {
		return errors.New("signature created in the future")
	}
	if created > 0 && now.After(time.Unix(created, 0).Add(maxSignatureAge)) {
		return errors.New("signature created too long ago")
	}
	if expires > 0 && now.After(time.Unix(expires, 0).Add(clockSkew)) {
		return errors.New("signature expired")
	}
	sigValue, err := parseSignature(sig, sigName)
	if err != nil {
		return err
	}

	// Build the signing string from the covered components.
	signingString, err := buildSigningString(r, covered)
	if err != nil {
		return err
	}

	// Verify the signature.
	pub, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(signingString))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigValue); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// clockSkew is the tolerance for created/expires timestamps.
const clockSkew = 5 * time.Minute

// maxSignatureAge is the maximum age of a signature's created timestamp.
const maxSignatureAge = 5 * time.Minute

// Verify implements cavage-12 HTTP Signatures.
func (cavageVerifier) Verify(r *http.Request, pubKeyPEM string) error {
	sigHeader := r.Header.Get("Signature")
	if sigHeader == "" {
		return errors.New("missing signature header")
	}

	// Parse the cavage signature: keyId="...",algorithm="rsa-sha256",headers="...",signature="..."
	params := parseCavageHeader(sigHeader)
	sigB64 := params["signature"]
	if sigB64 == "" {
		return errors.New("missing signature param")
	}
	sigValue, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Build the signing string from the headers param (default: date).
	headers := params["headers"]
	if headers == "" {
		headers = "date"
	}
	signingString, err := buildCavageSigningString(r, headers)
	if err != nil {
		return err
	}

	pub, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(signingString))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigValue); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// parseSignatureInput parses an RFC 9421 Signature-Input header, returning
// the signature name, covered components, and created/expires timestamps.
func parseSignatureInput(sigInput string) (name string, covered []string, created, expires int64, err error) {
	// Format: key1=("a" "b");created=123;expires=456
	eq := strings.Index(sigInput, "=")
	if eq < 0 {
		return "", nil, 0, 0, errors.New("invalid signature-input")
	}
	name = strings.TrimSpace(sigInput[:eq])
	rest := sigInput[eq+1:]
	// Extract the parenthesized component list.
	open := strings.Index(rest, "(")
	closeIdx := strings.Index(rest, ")")
	if open < 0 || closeIdx < 0 || closeIdx <= open {
		return "", nil, 0, 0, errors.New("invalid signature-input components")
	}
	compStr := rest[open+1 : closeIdx]
	for _, c := range strings.Fields(compStr) {
		covered = append(covered, strings.Trim(c, `"`))
	}
	// Parse the ;created= and ;expires= parameters after the component list.
	params := rest[closeIdx+1:]
	for _, p := range strings.Split(params, ";") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "created=") {
			created, _ = strconv.ParseInt(strings.TrimSpace(p[len("created="):]), 10, 64)
		}
		if strings.HasPrefix(p, "expires=") {
			expires, _ = strconv.ParseInt(strings.TrimSpace(p[len("expires="):]), 10, 64)
		}
	}
	return name, covered, created, expires, nil
}

// parseSignature extracts the base64 signature for a named key.
// RFC 9421 format: "sig1=:base64value:" (colon-delimited).
func parseSignature(sig, name string) ([]byte, error) {
	for _, part := range strings.Split(sig, ",") {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(part[:eq]) == name {
			val := strings.TrimSpace(part[eq+1:])
			// Strip surrounding colons.
			val = strings.Trim(val, ":")
			return base64.StdEncoding.DecodeString(val)
		}
	}
	return nil, errors.New("signature not found")
}

// buildSigningString builds the RFC 9421 signing string. Structured field
// names like @method are emitted in their quoted form ("@method": GET).
func buildSigningString(r *http.Request, covered []string) (string, error) {
	var sb strings.Builder
	for i, c := range covered {
		if i > 0 {
			sb.WriteString("\n")
		}
		switch c {
		case "@method":
			sb.WriteString(`"@method": ` + r.Method)
		case "@target-uri":
			sb.WriteString(`"@target-uri": ` + r.URL.String())
		case "@request-target":
			sb.WriteString(`"@request-target": ` + strings.ToLower(r.Method) + " " + r.URL.RequestURI())
		case "host":
			sb.WriteString("host: " + r.Host)
		case "date":
			sb.WriteString("date: " + r.Header.Get("Date"))
		case "content-type":
			sb.WriteString("content-type: " + r.Header.Get("Content-Type"))
		case "digest":
			sb.WriteString("digest: " + r.Header.Get("Digest"))
		default:
			sb.WriteString(c + ": " + r.Header.Get(c))
		}
	}
	return sb.String(), nil
}

// buildCavageSigningString builds the cavage-12 signing string.
func buildCavageSigningString(r *http.Request, headers string) (string, error) {
	var sb strings.Builder
	parts := strings.Split(headers, " ")
	for i, h := range parts {
		if i > 0 {
			sb.WriteString("\n")
		}
		switch h {
		case "(request-target)":
			sb.WriteString("(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI())
		case "host":
			sb.WriteString("host: " + r.Host)
		default:
			sb.WriteString(h + ": " + r.Header.Get(h))
		}
	}
	return sb.String(), nil
}

// parseCavageHeader parses a cavage-12 Signature header.
func parseCavageHeader(sig string) map[string]string {
	params := map[string]string{}
	for _, part := range strings.Split(sig, ",") {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		val := strings.Trim(strings.TrimSpace(part[eq+1:]), `"`)
		params[key] = val
	}
	return params
}

// parsePublicKey parses an RSA public key from PEM.
func parsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try PKCS1.
		rsaPub, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		return rsaPub, nil
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}
