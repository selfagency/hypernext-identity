package tenant

import "testing"

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"ipv6 with port", "[::1]:8080", "::1"},
		{"mixed case trailing dot", "Alice.Example.COM.", "alice.example.com"},
		{"hostname with port", "example.com:443", "example.com"},
		{"bare host unchanged", "alice.example.com", "alice.example.com"},
		{"bare ipv6 unchanged", "::1", "::1"},
		{"uppercase bare host", "ALICE.EXAMPLE.COM", "alice.example.com"},
		{"trailing dot only", "alice.example.com.", "alice.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeHost(tt.host); got != tt.want {
				t.Fatalf("NormalizeHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
