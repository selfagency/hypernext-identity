package nodeinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testConfig() Config {
	return Config{
		SoftwareName:      "hypernext-identity",
		SoftwareVersion:   "0.1.0",
		Protocols:         []string{"activitypub", "atproto"},
		OpenRegistrations: true,
		TotalUsers:        3,
	}
}

// TestHandlerServesNodeInfo verifies a valid NodeInfo 2.1 document.
func TestHandlerServesNodeInfo(t *testing.T) {
	req := httptest.NewRequest("GET", "/nodeinfo/2.1", http.NoBody)
	rec := httptest.NewRecorder()
	Handler(testConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var doc NodeInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid NodeInfo JSON: %v", err)
	}
	if doc.Version != "2.1" {
		t.Fatalf("version = %q, want 2.1", doc.Version)
	}
	if doc.Software.Name != "hypernext-identity" {
		t.Fatalf("software name = %q", doc.Software.Name)
	}
	if len(doc.Protocols) != 2 || doc.Protocols[0] != "activitypub" {
		t.Fatalf("protocols = %v", doc.Protocols)
	}
	if !doc.OpenRegistrations {
		t.Fatal("open registrations should be true")
	}
	if doc.Usage.Users.Total != 3 {
		t.Fatalf("total users = %d, want 3", doc.Usage.Users.Total)
	}
}

// TestHandlerEmptyServices verifies services arrays are present (not null).
func TestHandlerEmptyServices(t *testing.T) {
	req := httptest.NewRequest("GET", "/nodeinfo/2.1", http.NoBody)
	rec := httptest.NewRecorder()
	Handler(testConfig()).ServeHTTP(rec, req)

	var doc NodeInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Services.Inbound == nil || doc.Services.Outbound == nil {
		t.Fatal("services arrays should be non-nil (empty, not null)")
	}
}
