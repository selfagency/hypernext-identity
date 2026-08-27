package keys

import (
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// loadFixture reads a test fixture file.
func loadFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

// TestParsePGPPublicKeyValid verifies a valid armored public key parses.
func TestParsePGPPublicKeyValid(t *testing.T) {
	raw := loadFixture(t, "pub.asc")
	k, err := ParsePGPPublicKey(raw)
	if err != nil {
		t.Fatalf("ParsePGPPublicKey: %v", err)
	}
	if k.Fingerprint == "" {
		t.Fatal("empty fingerprint")
	}
	if len(k.Identities) == 0 {
		t.Fatal("no identities extracted")
	}
	if !strings.Contains(k.Armored, "PGP PUBLIC KEY BLOCK") {
		t.Fatalf("armored output missing block type: %q", k.Armored)
	}
}

// TestParsePGPPublicKeyRejectsPrivate verifies a private key block is rejected.
func TestParsePGPPublicKeyRejectsPrivate(t *testing.T) {
	// Generate a real private key at runtime (never commit key material).
	entity, err := openpgp.NewEntity("Test User", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	w, err := armor.Encode(&buf, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := ParsePGPPublicKey(buf.String()); err == nil {
		t.Fatal("expected error for private key block")
	}
}

// TestParsePGPPublicKeyMalformed verifies malformed input is rejected.
func TestParsePGPPublicKeyMalformed(t *testing.T) {
	if _, err := ParsePGPPublicKey("not armored"); err == nil {
		t.Fatal("expected error for malformed input")
	}
}

// TestParsePGPPublicKeyOversized verifies oversized input is rejected.
func TestParsePGPPublicKeyOversized(t *testing.T) {
	big := strings.Repeat("a", 513*1024)
	if _, err := ParsePGPPublicKey(big); err == nil {
		t.Fatal("expected error for oversized input")
	}
}
