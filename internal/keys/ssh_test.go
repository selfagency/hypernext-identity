package keys

import (
	"strings"
	"testing"
)

// testSSHKey is a valid ed25519 public key.
const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com"

// TestParseSSHPublicKeyValid verifies a valid key parses.
func TestParseSSHPublicKeyValid(t *testing.T) {
	k, err := ParseSSHPublicKey(testSSHKey)
	if err != nil {
		t.Fatalf("ParseSSHPublicKey: %v", err)
	}
	if k.Fingerprint == "" {
		t.Fatal("empty fingerprint")
	}
	if k.Algorithm != "ssh-ed25519" {
		t.Fatalf("algorithm = %s, want ssh-ed25519", k.Algorithm)
	}
	if k.Comment != "test@example.com" {
		t.Fatalf("comment = %q", k.Comment)
	}
	// Canonical line must be re-marshaled, not raw.
	if !strings.Contains(k.Line, "ssh-ed25519") {
		t.Fatalf("canonical line missing type: %q", k.Line)
	}
}

// TestParseSSHPublicKeyMalformed verifies malformed input is rejected.
func TestParseSSHPublicKeyMalformed(t *testing.T) {
	if _, err := ParseSSHPublicKey("not a key"); err == nil {
		t.Fatal("expected error for malformed key")
	}
}

// TestParseSSHPublicKeyOversized verifies oversized input is rejected.
func TestParseSSHPublicKeyOversized(t *testing.T) {
	big := strings.Repeat("a", 9*1024)
	if _, err := ParseSSHPublicKey(big); err == nil {
		t.Fatal("expected error for oversized input")
	}
}

// TestParseSSHPublicKeyMultiKey verifies multi-key input is rejected.
func TestParseSSHPublicKeyMultiKey(t *testing.T) {
	multi := testSSHKey + "\n" + testSSHKey
	if _, err := ParseSSHPublicKey(multi); err == nil {
		t.Fatal("expected error for multi-key input")
	}
}

// TestSameFingerprint verifies constant-time comparison.
func TestSameFingerprint(t *testing.T) {
	if !sameFingerprint("abc", "abc") {
		t.Fatal("identical fingerprints should match")
	}
	if sameFingerprint("abc", "abd") {
		t.Fatal("different fingerprints should not match")
	}
}
