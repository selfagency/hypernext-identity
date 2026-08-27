package activitypub

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hypernext/identity/internal/tenant"
)

// testKey generates an RSA key and returns the PEM public key + private key.
func testKey(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return pemStr, priv
}

// withTenant wraps a handler with the tenant middleware.
func withTenant(h http.Handler, handle string) http.Handler {
	store := fakeTenantStore{tenants: map[string]*tenant.Tenant{handle: {ID: "t1", Handle: handle}}}
	return tenant.Middleware(store)(h)
}

type fakeTenantStore struct{ tenants map[string]*tenant.Tenant }

func (f fakeTenantStore) FindByHost(_ context.Context, host string) (*tenant.Tenant, error) {
	t, ok := f.tenants[host]
	if !ok {
		return nil, tenant.ErrNotFound
	}
	return t, nil
}

// TestServeActor verifies the actor document.
func TestServeActor(t *testing.T) {
	pemStr, _ := testKey(t)
	h := withTenant(ServeActor(ActorConfig{Handle: "alice.example.com", PublicKeyPEM: pemStr}), "alice.example.com")
	req := httptest.NewRequest("GET", "/actor", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/activity+json" {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"type":"Person"`) {
		t.Fatalf("body missing Person type: %q", body)
	}
	if !strings.Contains(body, "alice.example.com/actor") {
		t.Fatalf("body missing actor URL: %q", body)
	}
	if !strings.Contains(body, "main-key") {
		t.Fatalf("body missing public key: %q", body)
	}
}

// TestServeActorNoTenant verifies a missing tenant is a 404.
func TestServeActorNoTenant(t *testing.T) {
	pemStr, _ := testKey(t)
	req := httptest.NewRequest("GET", "/actor", http.NoBody)
	rec := httptest.NewRecorder()
	ServeActor(ActorConfig{Handle: "alice.example.com", PublicKeyPEM: pemStr}).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no tenant = %d, want 404", rec.Code)
	}
}

// signRFC9421 signs a request using RFC 9421 format (quoted structured-field
// names per the spec).
func signRFC9421(r *http.Request, priv *rsa.PrivateKey) {
	// Signing string: "@request-target" host date
	signingString := `"@request-target": ` + strings.ToLower(r.Method) + " " + r.URL.RequestURI() +
		"\nhost: " + r.Host +
		"\ndate: " + r.Header.Get("Date")
	digest := sha256.Sum256([]byte(signingString))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	// created = now so the freshness check passes.
	r.Header.Set("Signature-Input", `sig1=("@request-target" "host" "date");created=`+itoa(time.Now().Unix()))
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

// signCavage signs a request using cavage-12 format.
func signCavage(r *http.Request, priv *rsa.PrivateKey) {
	signingString := "(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI() +
		"\nhost: " + r.Host +
		"\ndate: " + r.Header.Get("Date")
	digest := sha256.Sum256([]byte(signingString))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	r.Header.Set("Signature", `keyId="https://alice.example.com/actor#main-key",algorithm="rsa-sha256",headers="(request-target) host date",signature="`+base64.StdEncoding.EncodeToString(sig)+`"`)
}

// TestVerifyRFC9421 verifies an RFC 9421 signature.
func TestVerifyRFC9421(t *testing.T) {
	pemStr, priv := testKey(t)
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Date", "Tue, 26 Aug 2026 20:00:00 GMT")
	signRFC9421(req, priv)

	if err := NewRFC9421Verifier().Verify(req, pemStr); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerifyCavage verifies a cavage-12 signature.
func TestVerifyCavage(t *testing.T) {
	pemStr, priv := testKey(t)
	req := httptest.NewRequest("POST", "/inbox/", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Date", "Fri, 26 Aug 2026 20:00:00 GMT")
	signCavage(req, priv)

	if err := NewCavageVerifier().Verify(req, pemStr); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerifyDoubleKnock verifies RFC 9421 preferred, cavage fallback.
func TestVerifyDoubleKnock(t *testing.T) {
	pemStr, priv := testKey(t)

	// RFC 9421 path.
	rfcReq := httptest.NewRequest("POST", "/inbox", http.NoBody)
	rfcReq.Host = "alice.example.com"
	rfcReq.Header.Set("Date", "Fri, 26 Aug 2026 20:00:00 GMT")
	signRFC9421(rfcReq, priv)
	if err := VerifyDoubleKnock(rfcReq, pemStr, NewRFC9421Verifier(), NewCavageVerifier()); err != nil {
		t.Fatalf("RFC 9421 double-knock: %v", err)
	}

	// Cavage fallback (no Signature-Input header).
	cavReq := httptest.NewRequest("POST", "/inbox", http.NoBody)
	cavReq.Host = "alice.example.com"
	cavReq.Header.Set("Date", "Fri, 26 Aug 2026 20:00:00 GMT")
	signCavage(cavReq, priv)
	if err := VerifyDoubleKnock(cavReq, pemStr, NewRFC9421Verifier(), NewCavageVerifier()); err != nil {
		t.Fatalf("cavage double-knock: %v", err)
	}
}

// TestVerifyTampered verifies a tampered body fails.
func TestVerifyTampered(t *testing.T) {
	pemStr, priv := testKey(t)
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Date", "Fri, 26 Aug 2026 20:00:00 GMT")
	signRFC9421(req, priv)
	// Tamper: change the date after signing.
	req.Header.Set("Date", "Fri, 26 Aug 2026 21:00:00 GMT")

	if err := NewRFC9421Verifier().Verify(req, pemStr); err == nil {
		t.Fatal("expected verification failure on tampered request")
	}
}

// TestVerifyMissingHeaders verifies missing signature headers fail.
func TestVerifyMissingHeaders(t *testing.T) {
	pemStr, _ := testKey(t)
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	if err := NewRFC9421Verifier().Verify(req, pemStr); err == nil {
		t.Fatal("expected error for missing signature headers")
	}
}

// TestVerifyInvalidPEM verifies an invalid public key PEM fails.
func TestVerifyInvalidPEM(t *testing.T) {
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	req.Header.Set("Signature-Input", `sig1=("@request-target")`)
	req.Header.Set("Signature", "sig1=:AAAA:")
	if err := NewRFC9421Verifier().Verify(req, "not-a-pem"); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

// TestVerifyInvalidSignatureInput verifies malformed Signature-Input fails.
func TestVerifyInvalidSignatureInput(t *testing.T) {
	pemStr, _ := testKey(t)
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	req.Header.Set("Signature-Input", "malformed")
	req.Header.Set("Signature", "sig1=:AAAA:")
	if err := NewRFC9421Verifier().Verify(req, pemStr); err == nil {
		t.Fatal("expected error for malformed signature-input")
	}
}

// TestVerifySignatureNotFound verifies a missing named signature fails.
func TestVerifySignatureNotFound(t *testing.T) {
	pemStr, _ := testKey(t)
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	req.Header.Set("Signature-Input", `sig1=("@request-target")`)
	req.Header.Set("Signature", "other=:AAAA:")
	if err := NewRFC9421Verifier().Verify(req, pemStr); err == nil {
		t.Fatal("expected error for missing named signature")
	}
}

// TestVerifyCavageMissingSignature verifies a cavage request without a
// signature param fails.
func TestVerifyCavageMissingSignature(t *testing.T) {
	pemStr, _ := testKey(t)
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	req.Header.Set("Signature", `keyId="x",algorithm="rsa-sha256"`)
	if err := NewCavageVerifier().Verify(req, pemStr); err == nil {
		t.Fatal("expected error for missing signature param")
	}
}

// TestVerifyCavageNoHeader verifies a cavage request without a Signature
// header fails.
func TestVerifyCavageNoHeader(t *testing.T) {
	pemStr, _ := testKey(t)
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	if err := NewCavageVerifier().Verify(req, pemStr); err == nil {
		t.Fatal("expected error for missing signature header")
	}
}

// TestParsePublicKeyPKCS1 verifies PKCS1 public key parsing.
func TestParsePublicKeyPKCS1(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)})
	pub, err := parsePublicKey(string(pkcs1))
	if err != nil {
		t.Fatalf("parsePublicKey PKCS1: %v", err)
	}
	if pub.N == nil {
		t.Fatal("expected non-nil public key")
	}
}

// TestParsePublicKeyNotRSA verifies a non-RSA key fails.
func TestParsePublicKeyNotRSA(t *testing.T) {
	// An EC key is not RSA.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})
	if _, err := parsePublicKey(string(ecPEM)); err == nil {
		t.Fatal("expected error for non-RSA key")
	}
}

// TestBuildSigningString verifies the covered-component branches.
func TestBuildSigningString(t *testing.T) {
	req := httptest.NewRequest("POST", "/inbox", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Date", "Fri, 26 Aug 2026 20:00:00 GMT")
	req.Header.Set("Content-Type", "application/activity+json")
	req.Header.Set("Digest", "sha-256=abc")

	covered := []string{"@method", "@target-uri", "@request-target", "host", "date", "content-type", "digest", "custom"}
	ss, err := buildSigningString(req, covered)
	if err != nil {
		t.Fatalf("buildSigningString: %v", err)
	}
	if !strings.Contains(ss, `"@method": POST`) {
		t.Fatalf("missing @method: %q", ss)
	}
	if !strings.Contains(ss, `"@target-uri": /inbox`) {
		t.Fatalf("missing @target-uri: %q", ss)
	}
	if !strings.Contains(ss, `"@request-target": post /inbox`) {
		t.Fatalf("missing @request-target: %q", ss)
	}
	if !strings.Contains(ss, "host: alice.example.com") {
		t.Fatalf("missing host: %q", ss)
	}
	if !strings.Contains(ss, "content-type: application/activity+json") {
		t.Fatalf("missing content-type: %q", ss)
	}
	if !strings.Contains(ss, "digest: sha-256=abc") {
		t.Fatalf("missing digest: %q", ss)
	}
	if !strings.Contains(ss, "custom: ") {
		t.Fatalf("missing custom header: %q", ss)
	}
}

// TestParseCavageHeader verifies cavage header parsing.
func TestParseCavageHeader(t *testing.T) {
	params := parseCavageHeader(`keyId="x",algorithm="rsa-sha256",headers="date",signature="abc"`)
	if params["keyId"] != "x" || params["algorithm"] != "rsa-sha256" || params["signature"] != "abc" {
		t.Fatalf("params = %+v", params)
	}
}
