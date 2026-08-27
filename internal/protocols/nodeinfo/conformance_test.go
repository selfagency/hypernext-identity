package nodeinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSpecConformanceNodeInfo verifies the NodeInfo 2.1 document matches the
// schema exactly: version, software, protocols, services, openRegistrations,
// usage. https://nodeinfo.diaspora.software/protocol.html
func TestSpecConformanceNodeInfo(t *testing.T) {
	h := Handler(Config{
		SoftwareName:      "hypernext-identity",
		SoftwareVersion:   "0.1.0",
		Protocols:         []string{"solid", "remotestorage", "atproto"},
		OpenRegistrations: false,
		TotalUsers:        3,
	})
	req := httptest.NewRequest("GET", "/.well-known/nodeinfo", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// version must be "2.1" (NodeInfo 2.1 schema).
	if raw["version"] != "2.1" {
		t.Fatalf("version = %v, want 2.1", raw["version"])
	}

	// software must be an object with name + version.
	software, ok := raw["software"].(map[string]any)
	if !ok {
		t.Fatalf("software not an object: %v", raw["software"])
	}
	if software["name"] != "hypernext-identity" || software["version"] != "0.1.0" {
		t.Fatalf("software = %v", software)
	}

	// protocols must be an array.
	protocols, ok := raw["protocols"].([]any)
	if !ok || len(protocols) != 3 {
		t.Fatalf("protocols = %v, want 3", raw["protocols"])
	}

	// services must be an object with inbound + outbound arrays.
	services, ok := raw["services"].(map[string]any)
	if !ok {
		t.Fatalf("services not an object: %v", raw["services"])
	}
	if _, ok := services["inbound"].([]any); !ok {
		t.Fatalf("services.inbound not an array: %v", services["inbound"])
	}
	if _, ok := services["outbound"].([]any); !ok {
		t.Fatalf("services.outbound not an array: %v", services["outbound"])
	}

	// openRegistrations must be a boolean.
	if raw["openRegistrations"] != false {
		t.Fatalf("openRegistrations = %v, want false", raw["openRegistrations"])
	}

	// usage must be an object with users.total.
	usage, ok := raw["usage"].(map[string]any)
	if !ok {
		t.Fatalf("usage not an object: %v", raw["usage"])
	}
	users, ok := usage["users"].(map[string]any)
	if !ok {
		t.Fatalf("usage.users not an object: %v", usage["users"])
	}
	if users["total"] != float64(3) {
		t.Fatalf("usage.users.total = %v, want 3", users["total"])
	}
}
