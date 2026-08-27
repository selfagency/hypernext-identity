package chatfederation

import "testing"

// TestNormalizeLocalpart verifies lowercase + safe-character normalization.
func TestNormalizeLocalpart(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Alice", "alice"},
		{"Alice.Example", "alice.example"},
		{"alice@example", "alice-x40example"}, // @ escaped (injective)
		{"alice example", "alice-x20example"}, // space escaped (injective)
		{"alice_1", "alice_1"},
		{"", "user"},            // empty -> fallback
		{"@@@", "-x40-x40-x40"}, // all-disallowed -> escaped (injective)
		{"Ünïcode", "ünïcode"},  // unicode letters kept, lowercased
	}
	for _, c := range cases {
		if got := NormalizeLocalpart(c.in); got != c.want {
			t.Fatalf("NormalizeLocalpart(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestIsValidJIDNode verifies RFC 7622 JID node validity.
func TestIsValidJIDNode(t *testing.T) {
	valid := []string{"alice", "alice.example", "alice_1", "ünïcode"}
	for _, s := range valid {
		if !IsValidJIDNode(s) {
			t.Fatalf("IsValidJIDNode(%q) = false, want true", s)
		}
	}
	invalid := []string{"", " alice", "alice@example", "alice space", "alice:node"}
	for _, s := range invalid {
		if IsValidJIDNode(s) {
			t.Fatalf("IsValidJIDNode(%q) = true, want false", s)
		}
	}
}

// TestIsValidMatrixLocalpart verifies Matrix localpart validity.
func TestIsValidMatrixLocalpart(t *testing.T) {
	valid := []string{"alice", "alice.example", "alice_1", "ünïcode"}
	for _, s := range valid {
		if !IsValidMatrixLocalpart(s) {
			t.Fatalf("IsValidMatrixLocalpart(%q) = false, want true", s)
		}
	}
	// ':' is reserved for the domain separator in Matrix.
	invalid := []string{"", "alice:example", "alice@example", "alice example"}
	for _, s := range invalid {
		if IsValidMatrixLocalpart(s) {
			t.Fatalf("IsValidMatrixLocalpart(%q) = true, want false", s)
		}
	}
}

// TestNormalizeProducesValidBoth verifies the normalized output is valid as
// both a Matrix localpart and a JID node (the cross-cutting requirement).
func TestNormalizeProducesValidBoth(t *testing.T) {
	inputs := []string{"Alice Example", "alice@example.com", "Ünïcode User", "a b c"}
	for _, in := range inputs {
		out := NormalizeLocalpart(in)
		if !IsValidMatrixLocalpart(out) {
			t.Fatalf("normalized %q -> %q not a valid Matrix localpart", in, out)
		}
		if !IsValidJIDNode(out) {
			t.Fatalf("normalized %q -> %q not a valid JID node", in, out)
		}
	}
}

// TestNormalizeInjective verifies distinct inputs never collide (S13). The
// current implementation strips disallowed characters, so "Foo@Bar!" and
// "foobar" both normalize to "foobar". Normalization must be injective.
func TestNormalizeInjective(t *testing.T) {
	pairs := [][2]string{
		{"Foo@Bar!", "foobar"},
		{"a b", "ab"},
		{"alice@example", "aliceexample"},
		{"alice example", "aliceexample"},
	}
	for _, p := range pairs {
		if NormalizeLocalpart(p[0]) == NormalizeLocalpart(p[1]) {
			t.Fatalf("collision: NormalizeLocalpart(%q) == NormalizeLocalpart(%q) == %q", p[0], p[1], NormalizeLocalpart(p[0]))
		}
	}
}
