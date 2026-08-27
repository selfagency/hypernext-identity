// Package keys implements the public key hosting module. It is publish-only:
// no private key material ever touches the server. SSH and PGP public keys
// are validated, stored in canonical form, and served via GitHub/GitLab-style
// endpoints and WKD.
package keys

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHKey is a parsed SSH public key.
type SSHKey struct {
	Fingerprint string
	Algorithm   string
	Comment     string
	Line        string // canonical re-marshaled line, not raw user input
}

// ParseSSHPublicKey validates an SSH public key and returns its canonical
// form. It rejects oversized, malformed, and multi-key input.
func ParseSSHPublicKey(raw string) (*SSHKey, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 8*1024 {
		return nil, errors.New("keys: input too large to be a valid public key")
	}
	pub, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("keys: not a valid SSH public key: %w", err)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("keys: input must contain exactly one key")
	}
	return &SSHKey{
		Fingerprint: ssh.FingerprintSHA256(pub),
		Algorithm:   pub.Type(),
		Comment:     comment,
		Line:        string(ssh.MarshalAuthorizedKey(pub)),
	}, nil
}

// sameFingerprint compares fingerprints in constant time.
func sameFingerprint(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
