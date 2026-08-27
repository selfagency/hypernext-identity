package keys

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// PGPKey is a parsed OpenPGP public key.
type PGPKey struct {
	Fingerprint string
	Algorithm   string
	Identities  []string
	ExpiresAt   *time.Time
	Armored     string
}

// ParsePGPPublicKey validates an ASCII-armored key block and refuses
// anything containing private key material. Fail closed on the armor type
// first, before any parsing that might partially succeed on a private key
// block.
func ParsePGPPublicKey(raw string) (*PGPKey, error) {
	if len(raw) > 512*1024 {
		return nil, errors.New("keys: input too large to be a reasonable public key")
	}

	block, err := armor.Decode(strings.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("keys: not a valid armored OpenPGP block: %w", err)
	}

	if block.Type != "PGP PUBLIC KEY BLOCK" {
		return nil, fmt.Errorf("keys: expected a public key block, got %q — private keys are never accepted", block.Type)
	}

	keyring, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, fmt.Errorf("keys: failed to parse key: %w", err)
	}
	if len(keyring) != 1 {
		return nil, errors.New("keys: submit exactly one key at a time")
	}
	entity := keyring[0]

	if entity.PrivateKey != nil {
		// Defense in depth: refuse unconditionally if a private key packet
		// is present, even if the armor type already gated this.
		return nil, errors.New("keys: private key material detected, refusing to store")
	}

	var identities []string
	for _, ident := range entity.Identities {
		identities = append(identities, ident.Name)
	}

	var expires *time.Time
	if entity.PrimaryKey != nil {
		if sig, _ := entity.PrimarySelfSignature(); sig != nil && sig.KeyLifetimeSecs != nil {
			t := entity.PrimaryKey.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
			expires = &t
		}
	}

	var out strings.Builder
	w, err := armor.Encode(&out, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return nil, err
	}
	if err := entity.Serialize(w); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	return &PGPKey{
		Fingerprint: fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint),
		Algorithm:   fmt.Sprintf("%d", entity.PrimaryKey.PubKeyAlgo),
		Identities:  identities,
		ExpiresAt:   expires,
		Armored:     out.String(),
	}, nil
}
