package activitypub

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signRFC9421Quoted signs a request using the spec-compliant quoted
// "@method": GET form over the given covered components with an explicit
// created timestamp.
func signRFC9421Quoted(r *http.Request, priv *rsa.PrivateKey, covered []string, created int64) {
	var sb strings.Builder
	for i, c := range covered {
		if i > 0 {
			sb.WriteString("\n")
		}
		switch c {
		case "@method":
			sb.WriteString(`"@method": GET`)
		case "host":
			sb.WriteString("host: " + r.Host)
		case "date":
			sb.WriteString("date: " + r.Header.Get("Date"))
		default:
			sb.WriteString(c + ": " + r.Header.Get(c))
		}
	}
	digest := sha256.Sum256([]byte(sb.String()))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	compStr := ""
	for i, c := range covered {
		if i > 0 {
			compStr += " "
		}
		compStr += `"` + c + `"`
	}
	r.Header.Set("Signature-Input", `sig1=(`+compStr+`);created=`+itoa(created))
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestRFC9421QuotedMethod verifies the RFC 9421 signing string uses the
// quoted "@method": GET form (S9). The current naive parser emits
// "@method: GET" which produces a different signing string.
func TestRFC9421QuotedMethod(t *testing.T) {
	pemStr, priv := testKey(t)
	r := httptest.NewRequest("GET", "https://example.com/inbox", http.NoBody)
	r.Host = "example.com"

	signRFC9421Quoted(r, priv, []string{"@method", "host"}, time.Now().Unix())

	v := NewRFC9421Verifier()
	if err := v.Verify(r, pemStr); err != nil {
		t.Fatalf("RFC 9421 quoted @method verification failed: %v", err)
	}
}

// TestRFC9421RejectsStaleCreated verifies a signature with an expired
// `created` timestamp is rejected (S9 replay protection).
func TestRFC9421RejectsStaleCreated(t *testing.T) {
	pemStr, priv := testKey(t)
	r := httptest.NewRequest("GET", "https://example.com/inbox", http.NoBody)
	r.Host = "example.com"

	// created = 1 hour ago (stale).
	signRFC9421Quoted(r, priv, []string{"@method", "host"}, time.Now().Add(-time.Hour).Unix())

	v := NewRFC9421Verifier()
	if err := v.Verify(r, pemStr); err == nil {
		t.Fatal("stale created timestamp accepted — replay possible")
	}
}

// TestVerifyDoubleKnockNoDowngrade verifies a malformed RFC 9421 signature
// does NOT silently fall back to cavage (S9). If Signature-Input is present
// but invalid, verification must fail closed.
func TestVerifyDoubleKnockNoDowngrade(t *testing.T) {
	pemStr, priv := testKey(t)
	r := httptest.NewRequest("GET", "https://example.com/inbox", http.NoBody)
	r.Host = "example.com"
	r.Header.Set("Date", "Fri, 26 Aug 2026 20:00:00 GMT")

	// Present a malformed Signature-Input (invalid base64 signature) with a
	// valid cavage signature. The double-knock must NOT fall back to cavage.
	r.Header.Set("Signature-Input", `sig1=("@method" "host");created=0`)
	signCavage(r, priv) // sets a valid cavage Signature header

	rfc := NewRFC9421Verifier()
	cavage := NewCavageVerifier()
	if err := VerifyDoubleKnock(r, pemStr, rfc, cavage); err == nil {
		t.Fatal("malformed RFC signature silently downgraded to cavage")
	}
}
